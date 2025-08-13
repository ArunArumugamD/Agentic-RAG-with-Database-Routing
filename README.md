# Agentic RAG with Database Routing

## ThreatRAG - Intelligent database routing for threat intelligence

A sophisticated dual-database RAG system that intelligently routes queries between PostgreSQL (structured data) and Qdrant (vector search) for comprehensive threat intelligence analysis. 

## Key Features

- **Intelligent Query Routing**: Automatically chooses optimal database based on query type
- **Dual Database Architecture**: PostgreSQL for structured CVEs + Qdrant for semantic search
- **Self-Correcting Search**: 7 retry strategies for improved results
- **Real Threat Data**: 10+ legendary CVEs with enhanced aliases (Meltdown, Spectre, Log4j, etc.)
- **Web UI**: Clean, responsive interface with real-time search
- **Fast Response**: Sub-100ms query response times
- **No API Keys Required**: Uses Groq's free tier for LLM capabilities

## Tech Stack

- **Backend**: FastAPI (Python 3.11+)
- **Databases**: PostgreSQL + Qdrant Vector DB
- **LLM**: DeepSeek R1 via Groq (free tier)
- **Embeddings**: all-MiniLM-L6-v2 (384 dimensions)
- **Frontend**: Vanilla JavaScript + CSS
- **Containerization**: Docker Compose

## System Architecture

```
User Query → Query Classifier → Route Decision
                                      ↓
                    ┌─────────────────┴─────────────────┐
                    ↓                                   ↓
            PostgreSQL (Structured)            Qdrant (Semantic)
            - CVE records                      - Vector embeddings
            - CVSS scores                      - Document search
            - Severity filters                 - Similarity matching
                    ↓                                   ↓
                    └─────────────────┬─────────────────┘
                                      ↓
                            Result Deduplication
                                      ↓
                                Web Interface
```

## Quick Start

### Prerequisites
- Python 3.11+
- Docker Desktop
- PostgreSQL (or use Docker)
- 4GB RAM minimum

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/ArunArumugamD/Agentic-RAG-with-Database-Routing.git
cd Agentic-RAG-with-Database-Routing
```

2. **Set up environment**
```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

3. **Configure environment variables**
```bash
# Create .env file with:
DATABASE_URL=postgresql://user:password@localhost/threat_intel
GROQ_API_KEY=your_free_groq_key  # Get from console.groq.com
QDRANT_URL=http://localhost:6333
```

4. **Start Docker services**
```bash
docker-compose up -d
# This starts PostgreSQL, Qdrant, and Redis
```

5. **Initialize databases**
```bash
# Run database migrations
python scripts/init_database.py

# Collect threat data (optional)
python scripts/collect_cve_data.py
```

6. **Start the application**
```bash
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
```

7. **Access the UI**
```
http://localhost:8000
```

## Example Queries

### Specific CVE Lookup
```
CVE-2021-44228
Meltdown vulnerability
Log4j remote code execution
```

### Broad Security Searches
```
Critical CVE vulnerabilities
Apache vulnerabilities
Windows CVEs published recently
High CVSS score vulnerabilities
```

### Semantic Searches
```
Similar to Heartbleed
Explain buffer overflow
Related ransomware attacks
```

## Performance

- **Response Time**: 80-100ms average
- **Vector Search**: 12,740+ embedded documents
- **Relevance Scoring**: 50-70% for targeted queries
- **Database Coverage**: 10 legendary CVEs + recent vulnerabilities

## Routing Intelligence

| Query Type | Database Used | Example |
|------------|--------------|---------|
| Specific CVE | PostgreSQL | "CVE-2021-44228" |
| Semantic Search | Qdrant | "Similar to Log4j" |
| Security Query | Hybrid | "Critical vulnerabilities" |
| Unknown Terms | Both | "Purple team exercises" |

## Project Structure

```
├── src/
│   ├── api/              # FastAPI endpoints
│   ├── routing/          # Query routing logic
│   ├── database/         # PostgreSQL adapter
│   └── vector_store/     # Qdrant adapter
├── static/               # Web UI files
├── scripts/              # Data collection scripts
├── docker-compose.yml    # Container orchestration
└── .env                  # Configuration (not in repo)
```

## Acknowledgments

- NVD for CVE data
- AlienVault OTX for threat intelligence
- Groq for free LLM access
- Open-source community

---