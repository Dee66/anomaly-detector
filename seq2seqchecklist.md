eq2Seq Answer Architect - Delivery Checklist
<div align="left" style="margin:1rem 0;"> <strong>Status:</strong> <span>0% complete (0/75 items)</span> <div style="display:flex; align-items:center; gap:0.75rem; margin-top:0.35rem;"> <div style="flex:1; height:14px; background:#1f2933; border-radius:999px; overflow-hidden;"> <div style="width:0%; height:100%; background:linear-gradient(90deg, #10b981, #22d3ee);"></div> </div> <code style="background:#0f172a; color:#ecfeff; padding:0.1rem 0.55rem; border-radius:999px; font-weight:600;">0%</code> </div> </div>
1. Environment & Tooling 🛠️
[ ] Confirm Python 3.11 toolchain installed locally

[ ] Initialize Poetry project with RAG/LLM dependencies (LangChain, Bedrock SDK, OpenSearch client)

[ ] Define default Nox sessions (lint, tests, format, e2e_latency, package)

[ ] Integrate AWS CLI v2.27.50 requirement and Bedrock access profile setup

[ ] Document the environment variable strategy for LLM selection (e.g., SA_LLM_PROVIDER)

2. Project Scaffolding 🧱
[ ] Finalize repo structure (infra/, src/rag_api/, src/orchestrator/, knowledge_base/, tests/)

[ ] Populate README with setup + demo steps for local RAG testing

3. Knowledge Base & Retrieval 🧠
[ ] Define corpus source (e.g., S3 zone) and ingestion contract (metadata, retention)

[ ] Implement chunking profile (size, overlap, metadata tags) for governance

[ ] Provision pgvector/OpenSearch instance via CDK with VPC-only access

[ ] Provision KMS-encrypted feature stores for entity embeddings

[ ] Implement data ingestion pipeline (S3 → Chunking → Embeddings → Vector Store)

[ ] Define index lifecycle policies (index rotation, index deletion) for cost control

[ ] Implement DLP inspector (e.g., PII scrubbing) before ingestion to the vector store

4. LLM & Embedding Strategy 🗃️
[ ] Select and configure primary Embedding Model (e.g., Titan Embed)

[ ] Define LLM Strategy (Amazon Bedrock endpoint vs. self-hosted SageMaker)

[ ] Version and manage prompt templates (system prompt, few-shot examples)

[ ] Define PEFT/LoRA strategy for future specialized fine-tuning

[ ] Notebook placeholders: 01-Prompt-Benchmarking, 02-Retrieval-Harness, 03-Cost-Modeling

5. Testing & Quality Gates ✅
[ ] Unit tests for vector retrieval (fixtures for vector ID lookups)

[ ] Unit tests for prompt construction/injection logic

[ ] End-to-end integration test (full RAG call to a mocked Bedrock API)

[ ] Implement RAG evaluation harness (MTEB/BEIR style) for relevance

[ ] Define quality gate: Retrieval Score (e.g., MRR@k) ≥ Baseline for CI pass

6. Retrieval & Prompt Service 📝
[ ] Define API contract: { query, session_id } \rightarrow \{ answer, sources, latency \}

[ ] Implement pre-inference guardrails (prompt toxicity/policy inspection)

[ ] Implement post-inference guardrails (output redaction/PII scrubbing)

[ ] Add structured logging for cost (token counts) and latency per stage

[ ] Package the RAG API service for containerization (Fargate/Lambda)

7. Infrastructure (CDK) 🏗️
[ ] Define Fargate/ECS service (or Lambda) for the RAG API frontend

[ ] Provision VPC Endpoint access to Bedrock, OpenSearch, and Secrets Manager

[ ] Enable tracing and observability with X-Ray integration

[ ] Add CloudWatch alarms for 5xx rate and P95 latency on the API Gateway

[ ] Tag resources (App, Env, CostCenter) for FinOps visibility

8. Latency-Paced RAG Orchestration ⏳
[ ] Document the Three-Stage Step Functions RAG workflow (Retrieval → Prompt → Inference)

[ ] Provision the state machine via CDK with least-privilege IAM

[ ] Implement concurrency controls and timeouts per branch in the state machine for cost control

[ ] Define Step Functions service integration for Managed Bedrock/SageMaker calls

[ ] Add CloudWatch alarms for state machine latency SLO breaches

9. Deployment & Operations 🔁
[ ] Implement blue/green promotion strategy for the Fargate/Lambda RAG service

[ ] Document SLO Fallback Playbook (e.g., shifting traffic to a lower-cost, lower-quality heuristic on P95 breach)

[ ] Provide teardown automation (Makefile/Nox session)

[ ] Capture CloudWatch dashboard screenshots showing Latency SLOs and Cost-per-Query

10. CI/CD 🔄
[ ] Update ci.yml (lint + unit/e2e tests + cdk synth)

[ ] Add a latency check stage in CI: fail if mock E2E latency > 100ms

[ ] Configure environment protection rules for prod deployment

11. Senior Leader Mandates · SLOs, PII & FinOps 💰
[ ] Define and implement CloudWatch SLO alarms for P95 Latency ≤320ms on the API

[ ] Implement PII/Data Egress Guardrail that blocks prompt construction if sensitive data is detected.

[ ] Establish Token Budget Alarm (CloudWatch metric filter on logs) routed to FinOps teams.

[ ] Apply S3 lifecycle policies for corpus/vector store backups (long-term cost optimization).

[ ] Provision scheduled Lambda to shut down non-prod vector stores after-hours for maximum savings.

12. Documentation & Interview Prep 📚
[ ] Draft ADR: Retrieval Boundary Strategy

[ ] Write runbooks (deploy, invoke, rollback, Latency SLO troubleshooting)

[ ] Prepare demo script + talking points emphasizing Step Functions for cost pacing and concurrency

[ ] Add FAQ section (latency, cost-per-query, LLM selection, RAG security)

[ ] Capture lessons learned / future enhancements (e.g., custom fine-tuning)