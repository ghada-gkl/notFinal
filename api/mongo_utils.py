import os
from pymongo import MongoClient
from dotenv import load_dotenv
from bson import ObjectId
import copy
from datetime import datetime
import re

# Load environment variables
load_dotenv()

# Configuration
MONGO_URI = os.getenv('MONGODB_URI')
DATABASE_NAME = os.getenv('MONGO_DATABASE')
COLLECTION_NAME = "alerts"
ATLAS_VECTOR_SEARCH_INDEX_NAME = os.getenv('ATLAS_VECTOR_SEARCH_INDEX_NAME')
def get_mongo_client():
    """Return a MongoDB client using the connection string."""
    return MongoClient(MONGO_URI)

def get_mongo_db():
    """Return the MongoDB database instance."""
    return get_mongo_client()[DATABASE_NAME]

def get_collections():
    """Get MongoDB collections."""
    db = get_mongo_db()
    return {
        'alerts': db['alerts'],
        'transactions': db['transactions'],
        'feedback': db['user_feedback']
    }
def parse_alert_message(alert_message):
    """Parse alert message into structured sub-alerts with transactions."""
    sub_alerts = []
    blocks = re.split(r'-{3,}\n', alert_message)  # Split on multiple dashes
    
    for block in blocks:
        block = block.strip()
        if not block or "**Alert:**" in block:
            continue  # Skip empty blocks and header
        
        # Extract components using regex
        alert_match = re.search(r'Alert: "(.*?)"', block)
        suggestion_match = re.search(r'Suggestion: "(.*?)"', block, re.DOTALL)
        transactions_match = re.search(r'Affected Transactions: "(.*?)"', block, re.DOTALL)

        if alert_match and suggestion_match:
            transactions = []
            if transactions_match:
                # Split transaction entries and parse key-value pairs
                transaction_entries = transactions_match.group(1).split('; ')
                for entry in transaction_entries:
                    entry = entry.strip()
                    if not entry:
                        continue
                    transaction = {}
                    parts = entry.split(', ')
                    for part in parts:
                        if ': ' in part:
                            key, value = part.split(': ', 1)
                            transaction[key.strip()] = value.strip()
                    if transaction:
                        transactions.append(transaction)
            
            sub_alerts.append({
                'message': alert_match.group(1),
                'suggestion': suggestion_match.group(1).replace('\n', ' '),
                'affected_transactions': transactions
            })
    
    return sub_alerts

def get_all_parsed_alerts(limit=3, skip=0):
    """Fetch all alerts with parsed message, suggestions, and transactions."""
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]
    alerts_collection = db[COLLECTION_NAME]
    
    alerts = list(alerts_collection.find({}).skip(skip).limit(limit))
    parsed_results = []
    
    for alert in alerts:
        sub_alerts = parse_alert_message(alert.get('alert_message', ''))
        for sub_alert in sub_alerts:
            parsed_results.append({
                'alert_id': str(alert['_id']),
                'timestamp': alert.get('timestamp'),
                'message': sub_alert['message'],
                'suggestion': sub_alert['suggestion'],
                'affected_transactions': sub_alert['affected_transactions']
            })
    
    return parsed_results

def get_parsed_alert(alert_id):
    """Get a single alert by ID with parsed message components."""
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]
    
    try:
        alert = db.alerts.find_one({'_id': ObjectId(alert_id)})
        if not alert:
            return None
        
        sub_alerts = parse_alert_message(alert.get('alert_message', ''))
        return {
            'alert_id': str(alert['_id']),
            'timestamp': alert.get('timestamp'),
            'sub_alerts': sub_alerts
        }
    except Exception as e:
        print(f"Error fetching alert: {str(e)}")
        return None
from bson import ObjectId
from pymongo.errors import PyMongoError

def submit_feedback(feedback_data):
    """Submit feedback for an alert with error handling."""
    client = MongoClient(MONGO_URI)
    db = client[DATABASE_NAME]
    
    try:
        # Validate alert_id format
        if not ObjectId.is_valid(feedback_data['alert_id']):
            raise ValueError("Invalid alert ID format")

        feedback_entry = {
            'alertId': ObjectId(feedback_data['alert_id']),
            'rating': feedback_data.get('rating', 0),
            'comment': feedback_data.get('comment', ''),
            'timestamp': datetime.utcnow()
        }

        result = db.feedback.insert_one(feedback_entry)
        return str(result.inserted_id)

    except PyMongoError as e:
        print(f"MongoDB Error: {str(e)}")
        return None
    except Exception as e:
        print(f"General Error: {str(e)}")
        return None
def parse_growth(growth):
    """Parse growth value from string or number."""
    if isinstance(growth, str):
        try:
            return float(growth.replace('%', '').strip())
        except (ValueError, AttributeError):
            return 0.0
    return float(growth) if growth else 0.0
from pymongo import MongoClient

def save_alert_to_collection(alert_data, collection_name):
    client = MongoClient()  # Adjust if you have a different MongoDB connection setup
    db = client['your_database']  # Replace with your actual database name
    collection = db[collection_name]
    collection.insert_one(alert_data) 
# mongo_utils.py
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
# Initialize components
embedder = SentenceTransformer('all-MiniLM-L6-v2')  # 384-dim embeddings

def vector_search(query: str, limit: int = 3):
    query = "DBIF_RSQL_INVALID_REQUEST errors in ST22 from WEBMETHODS user"  # Explicit query
    query_embedding = embedder.encode(query).tolist()
    
    # Vector search pipeline
    pipeline = [
        {
            "$vectorSearch": {
                "index": ATLAS_VECTOR_SEARCH_INDEX_NAME,
                "path": "embedding",
                "queryVector": query_embedding,
                "numCandidates": 200,
                "limit": limit,
                 "filter": { 
        "timestamp": { "$gte": "2025-02-01" }  # Target February 2025 alerts
    }
            }
        },
        {"$match": {  # Add keyword filters
            "$or": [
                { "error_status": "DBIF_RSQL_INVALID_REQUEST" },
                { "description": { "$regex": "ST22", "$options": "i" } }
            ]
        }},

        {
            "$project": {
                "_id": 0,
                "t_code": 1,
                "error_status": 1,
                "timestamp": 1,
                "description": 1,
                "score": {"$meta": "vectorSearchScore"}
            }
        }
    ]
    
    # Execute search
    db = get_mongo_db()
    return list(db[COLLECTION_NAME].aggregate(pipeline))

def rag_pipeline(query: str):
    """
    Process user query using the RAG pipeline.
    """
    # 1. Vector search
    results = vector_search(query)
    
    # 2. Format context for LLM
    context = "\n".join([
        f"t_code {res['t_code']} ({res['timestamp']}): {res['description']}"
        for res in results
    ])
    
    # 3. Generate response (replace with actual LLM call)
    response = f"Found {len(results)} related alerts:\n{context}"
    
    # 4. Extract transactions or alerts from the response
    transactions = [
        {
            "t_code": res["t_code"],
            "timestamp": res["timestamp"],
            "description": res["description"],
            "score": res.get("score", 0)
        }
        for res in results
    ]
    
    return response, transactions