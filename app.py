from fastapi import FastAPI, Request, HTTPException, Query, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError, OperationalError
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import urllib.parse
import logging
import re
from decimal import Decimal
from typing import List, Dict, Optional

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

# Security configuration
AGGREGATE_FUNCTIONS = {'AVG', 'COUNT', 'SUM', 'MIN', 'MAX', 'STDDEV'}
K_ANONYMITY_THRESHOLD = 3

def convert_decimals(obj):
    """Recursively convert Decimal to float"""
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_decimals(v) for v in obj]
    return obj

def contains_aggregate(query: str) -> bool:
    """Check if query contains aggregation functions"""
    return any(fn in query.upper() for fn in AGGREGATE_FUNCTIONS)

def validate_user_scope(query: str, user_id: str) -> bool:
    """Check if query contains user_id restriction"""
    pattern = re.compile(
        rf'\buser_?id\s*=\s*[\'"]?{re.escape(user_id)}[\'"]?',
        re.IGNORECASE
    )
    return bool(pattern.search(query))

def enforce_scope(query: str, user_id: str) -> str:
    """Add user_id restriction to query"""
    query_lower = query.lower()
    if ' where ' in query_lower:
        return f"{query} AND user_id = '{user_id}'"
    return f"{query} WHERE user_id = '{user_id}'"

def apply_k_anonymity(data: List[Dict]) -> List[Dict]:
    """Apply k-anonymity to results"""
    anonymized = []
    for row in data:
        anonymized_row = row.copy()
        if 'age' in anonymized_row:
            anonymized_row['age'] = f"{(row['age'] // 10) * 10}-{(row['age'] // 10 + 1) * 10}"
        if 'zip_code' in anonymized_row:
            anonymized_row['zip_code'] = row['zip_code'][:3] + "XXX"
        anonymized.append(anonymized_row)
    return anonymized

async def get_current_user(request: Request) -> User:
    """Get current user from headers"""
    return User(
        id=request.headers.get("X-User-ID", "admin"),
        role=request.headers.get("X-User-Role", "admin")
    )

@app.get("/query")
async def run_query(
    request: Request,
    sql: str = Query(..., min_length=1),
    current_user: User = Depends(get_current_user)
):
    """Execute a sanitized SQL query with inference controls"""
    try:
        # Decode URL-encoded SQL
        decoded_sql = urllib.parse.unquote(sql)
        logger.info(f"Received query: {decoded_sql}")

        # Block aggregate functions
        if contains_aggregate(decoded_sql):
            raise HTTPException(400, "Aggregate queries are not allowed")
        
        # Admin bypass
        if current_user.role == "admin":
            with Session() as session:
                result = session.execute(text(decoded_sql))
                data = [convert_decimals(dict(row._mapping)) for row in result]
            return JSONResponse({
                "data": data,
                "modified": False,
                "count": len(data)
            })
        
        # Normal user logic
        if validate_user_scope(decoded_sql, current_user.id):
            # Valid scope query - execute directly
            with Session() as session:
                result = session.execute(text(decoded_sql))
                data = [convert_decimals(dict(row._mapping)) for row in result]
            
            if len(data) > K_ANONYMITY_THRESHOLD:
                return JSONResponse({
                    "data": apply_k_anonymity(data),
                    "modified": True,
                    "count": len(data)
                })
            return JSONResponse({
                "data": data,
                "modified": False,
                "count": len(data)
            })
        else:
            # Enforce user scope
            modified_sql = enforce_scope(decoded_sql, current_user.id)
            logger.info(f"Modified query: {modified_sql}")
            
            with Session() as session:
                result = session.execute(text(modified_sql))
                data = [convert_decimals(dict(row._mapping)) for row in result]
            
            if len(data) > K_ANONYMITY_THRESHOLD:
                return JSONResponse({
                    "data": apply_k_anonymity(data),
                    "modified": True,
                    "count": len(data),
                    "note": "Query modified with k-anonymity"
                })
            return JSONResponse({
                "data": data,
                "modified": True,
                "count": len(data),
                "note": "Query modified to enforce user scope"
            })

    except HTTPException as he:
        logger.warning(f"Query rejected: {he.detail}")
        return JSONResponse(
            status_code=he.status_code,
            content={"error": he.detail}
        )
    except SQLAlchemyError as se:
        logger.error(f"Database error: {str(se)}")
        return JSONResponse(
            status_code=400,
            content={"error": "Database operation failed"}
        )
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"}
        )

@app.on_event("startup")
async def startup_event():
    """Initialize database connection"""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Database connection established")
    except OperationalError as e:
        logger.error(f"Database connection failed: {str(e)}")
        raise

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Serve the frontend interface"""
    return templates.TemplateResponse("index.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="debug",
        timeout_keep_alive=60
    )