import httpx
import json
import pathlib

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"
REGISTRY_PATH = pathlib.Path("../registry/tools.json")

def load_registry():
    return json.loads(REGISTRY_PATH.read_text())

async def ask_ai(prompt: str, context: dict = {}) -> str:
    tools = [t["name"] for t in load_registry() if t["ai_compatible"]]
    system = f"""You are VisionX AI — cybersecurity operational assistant embedded in an OS.
Active module: {context.get('module', 'none')}
Active target: {context.get('target', 'none')}
Available tools: {', '.join(tools)}

Rules:
- Return exact terminal commands when asked to run tools
- Be concise and operational
- Flag critical/high risk actions before executing
- No explanations unless asked"""

    payload = {
        "model": MODEL,
        "prompt": f"{system}\n\nUser: {prompt}",
        "stream": False
    }
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(OLLAMA_URL, json=payload)
        return r.json().get("response", "LLM offline")
