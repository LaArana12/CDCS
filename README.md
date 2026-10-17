# LLM-Powered Web API Security Testing Framework

An academic web API security testing framework that combines OpenAPI analysis, LLM-assisted attack-scenario generation, HTTP fuzzing, and structured reporting. The project is designed as a controlled lab for studying broken authorization and business-logic weaknesses in APIs.


## What it demonstrates

- **FastAPI target lab** - a deliberately vulnerable API with realistic authentication, profiles, products, orders, and administrative workflows.
- **OpenAPI parser** - extracts endpoints, parameters, request schemas, security requirements, and risk hints from an OpenAPI document.
- **Gemini-assisted scenario generator** - produces schema-validated attack scenarios, with a deterministic template fallback when an LLM is unavailable.
- **HTTP fuzzer** - executes scenarios against the lab, obtains runtime bearer tokens, redacts authorization headers, and records evidence.
- **Reporting dashboard** - exposes structured scan results through a lightweight HTML endpoint and JSON artifacts.

The current lab focuses on three API authorization and business-logic classes:

- **BOLA / IDOR** - accessing another user's order through an object identifier.
- **BFLA** - invoking administrative functions without the required role.
- **Mass Assignment** - injecting protected fields such as `role` into registration and profile-update requests.

## Repository layout

```text
Thuc_Nghiem_CSATTT/
├── 01_lab_api_test/                 # FastAPI target lab and PostgreSQL compose setup
├── 02_openapi_parser/               # OpenAPI endpoint and risk-hint extraction
├── 03_attack_scenario_generator_final/ # Template/Gemini scenario generation
├── 04_fuzzer_final/                 # Scenario execution and evidence collection
└── 05_experiment_data/              # Sanitized sample output artifacts
```

## Quick start

The target lab is intentionally vulnerable and should only be run in an isolated, local environment.

1. Prepare the runtime configuration:

   ```bash
   cd Thuc_Nghiem_CSATTT/01_lab_api_test
   cp .env.example .env
   # Replace every placeholder in .env with local-only values.
   ```

2. Start the PostgreSQL-backed FastAPI lab:

   ```bash
   docker compose up --build
   ```

   The API is available at `http://localhost:8000`; Swagger UI is at `http://localhost:8000/docs` and the scan dashboard is at `http://localhost:8000/scan-results`.

3. Parse the API contract:

   ```bash
   cd ../02_openapi_parser
   python parser.py --input openapi.json --output parser_output.json
   ```

4. Generate attack scenarios. The template mode does not require an external API key:

   ```bash
   cd ../03_attack_scenario_generator_final
   python attack_scenario_generator.py \
     --input ../02_openapi_parser/parser_output.json \
     --output attack_scenarios_generated.json \
     --mode template
   ```

   To use Gemini, set `GEMINI_API_KEY` or `GOOGLE_API_KEY` only in the local environment and choose `--mode gemini` or `--mode hybrid`. Never commit the key.

5. Run the fuzzer against the local lab:

   ```bash
   cd ../04_fuzzer_final
   python fuzzing_engine.py \
     --base-url http://localhost:8000 \
     --scenarios ../03_attack_scenario_generator_final/attack_scenarios_generated.json \
     --seed-context ../03_attack_scenario_generator_final/seed_context.json \
     --output ../05_experiment_data/scan_results_local.json
   ```

The fuzzer resolves account passwords from environment-variable references in `seed_context.json`, creates a fresh password for registration checks when needed, and redacts authorization headers from recorded evidence.

## Security and data-handling notes

- No database password, JWT signing key, Gemini key, or usable lab credential is committed.
- Copy `.env.example` to `.env`, use unique local values, and keep `.env` untracked.
- The committed scan artifact is a sanitized placeholder. Generate fresh results locally rather than committing response bodies that may contain credentials or password hashes.
- The API intentionally contains vulnerabilities for defensive testing. Do not expose it to the public internet or use it against systems without authorization.

## Portfolio relevance

This project demonstrates practical SOC and application-security skills: HTTP request/response analysis, API inventory, authentication-context handling, authorization testing, reproducible evidence collection, structured findings, and security-focused reporting. It is intended to complement a SOC Intern portfolio alongside networking, Linux, Wireshark, Nmap, Burp Suite, SIEM, and incident-response fundamentals.

