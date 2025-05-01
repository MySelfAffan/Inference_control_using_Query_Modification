from fastapi import FastAPI, Request, HTTPException, Query, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError, OperationalError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import urllib.parse
import logging
import re
from decimal import Decimal
from typing import List, Dict, Optional
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = "postgresql://kaif:@localhost/medical_db"
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
Session = sessionmaker(bind=engine)

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class User(BaseModel):
    id: str
    role: str
    department: Optional[str] = None
    condition: Optional[str] = None

# Authorization Views Configuration (Non-Truman Model)
AUTHORIZATION_VIEWS = {
    "admin": {
        "description": "Full access to all patient data",
        "query": "SELECT * FROM patients",
        "is_parameterized": False
    },
    "oncology": {
        "description": "Access to cancer patients only",
        "query": "SELECT * FROM patients WHERE \"medical_condition\" = 'Cancer'",
        "is_parameterized": False
    },
    "ortho": {
        "description": "Access to arthritis patients only",
        "query": "SELECT * FROM patients WHERE \"medical_condition\" = 'Arthritis'",
        "is_parameterized": False
    },
    "pulmonology": {
        "description": "Access to asthma patients only",
        "query": "SELECT * FROM patients WHERE \"medical_condition\" = 'Asthma'",
        "is_parameterized": False
    },
    "cardio": {
        "description": "Access to hypertension patients only",
        "query": "SELECT * FROM patients WHERE \"medical_condition\" = 'Hypertension'",
        "is_parameterized": False
    },
    "endocrine": {
        "description": "Access to obesity patients only",
        "query": "SELECT * FROM patients WHERE \"medical_condition\" = 'Obesity'",
        "is_parameterized": False
    }
}

# Parameterized Views (Example)
PARAMETERIZED_VIEWS = {
    "patient_by_id": {
        "query": "SELECT * FROM patients WHERE patient_id = :patient_id",
        "required_params": ["patient_id"]
    }
}

# Helpers
def convert_decimals(obj):
    """Recursively convert Decimal to float"""
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_decimals(v) for v in obj]
    return obj

def sanitize_query(query: str) -> bool:
    """Reject dangerous queries"""
    forbidden = ["DROP", "DELETE", "ALTER", "UPDATE", "INSERT", 
                "CREATE", "TRUNCATE", "GRANT", "REVOKE"]
    query_upper = query.upper()
    return any(keyword in query_upper for keyword in forbidden)

def get_user_view(user: User) -> str:
    """Get the authorization view SQL for the user's role"""
    if user.role == "admin":
        return AUTHORIZATION_VIEWS["admin"]["query"]
    if user.department in AUTHORIZATION_VIEWS:
        return AUTHORIZATION_VIEWS[user.department]["query"]
    raise HTTPException(status_code=403, detail="No authorization view defined for user role")

def check_unconditional_validity(query: str, user_view: str) -> bool:
    """
    Check if the query is unconditionally valid (can be answered using only the authorization view)
    Basic implementation - in a real system this would use query rewriting techniques
    """
    # Simple check: if the query is a selection on the authorized data
    if f"FROM patients" in query.upper() and user_view in query:
        return True
    return False

def rewrite_query_with_authorization(query: str, user: User) -> str:
    """
    Rewrite the query to enforce authorization (Non-Truman model)
    Returns the rewritten query or raises HTTPException if invalid
    """
    user_view = get_user_view(user)
    
    # For admin, no rewriting needed
    if user.role == "admin":
        return query
    
    # Check if query is already properly constrained
    if f"WHERE \"medical_condition\" = '{user.condition}'" in query.upper():
        return query
    
    # For simple SELECT queries, add the condition
    if query.strip().upper().startswith("SELECT"):
        # Parse the query to find existing WHERE clause
        where_pos = query.upper().find("WHERE")
        if where_pos == -1:
            # No WHERE clause, add one
            return f"{query} WHERE \"medical_condition\" = '{user.condition}'"
        else:
            # Has WHERE clause, add AND condition
            return f"{query} AND \"medical_condition\" = '{user.condition}'"
    
    # If we can't safely rewrite, reject the query
    raise HTTPException(
        status_code=403,
        detail="Query cannot be safely authorized. Try querying through your authorized view."
    )

async def get_current_user(request: Request) -> User:
    """Extract current user from headers with department info"""
    return User(
        id=request.headers.get("X-User-ID", "admin"),
        role=request.headers.get("X-User-Role", "admin"),
        department=request.headers.get("X-User-Dept"),
        condition=request.headers.get("X-Medical-Condition")
    )

# API endpoints
@app.get("/query")
async def run_query(
    request: Request,
    sql: str = Query(..., min_length=1),
    current_user: User = Depends(get_current_user)
):
    """Execute a query after Non-Truman model validation"""
    try:
        # Decode and log incoming SQL
        decoded_sql = urllib.parse.unquote(sql)
        logger.info(f"Received query from {current_user.id}: {decoded_sql}")

        # Check for dangerous operations
        if sanitize_query(decoded_sql):
            raise HTTPException(status_code=400, detail="Restricted query detected. Only SELECT operations are allowed.")

        # Non-Truman Model: Rewrite query to enforce authorization
        try:
            rewritten_sql = rewrite_query_with_authorization(decoded_sql, current_user)
        except HTTPException as he:
            # If we can't rewrite, check if query is unconditionally valid
            user_view = get_user_view(current_user)
            if not check_unconditional_validity(decoded_sql, user_view):
                raise he
        
        # Execute the rewritten query
        with Session() as session:
            result = session.execute(text(rewritten_sql))
            data = [convert_decimals(dict(row._mapping)) for row in result]

        return JSONResponse({
            "data": data,
            "authorized": True,
            "count": len(data),
            "note": f"Results filtered by {current_user.condition}" if current_user.condition else None
        })

    except HTTPException as he:
        logger.warning(f"Query rejected: {he.detail}")
        return JSONResponse(status_code=he.status_code, content={"error": he.detail})

    except SQLAlchemyError as se:
        logger.error(f"Database error: {str(se)}")
        return JSONResponse(status_code=500, content={"error": "Database error."})

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JSONResponse(status_code=500, content={"error": "Internal server error."})

@app.get("/views")
async def list_views(current_user: User = Depends(get_current_user)):
    """List available authorization views (for debugging)"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can list views")
    
    return JSONResponse({
        "authorization_views": AUTHORIZATION_VIEWS,
        "parameterized_views": PARAMETERIZED_VIEWS
    })

@app.on_event("startup")
async def startup_event():
    """Verify database connection and views at startup"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            # Verify patients table exists
            inspector = inspect(engine)
            if "patients" not in inspector.get_table_names():
                raise OperationalError("patients table not found in database")
        logger.info("Database connection established and schema validated.")
    except OperationalError as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Simple home endpoint"""
    return HTMLResponse(content="<h1>Medical Research Portal</h1><p>Backend server is running.</p>")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
