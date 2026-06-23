from fastapi import FastAPI
from pydantic import BaseModel
from database import SessionLocal, PacketLog
import time
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware
from iptables_converter  import convert_all_rules
from nftables_converter  import convert_to_nftables, convert_all_rules_nft
from firewall_service    import firewall_service
from rule_analyzer       import detect_shadow_rules, detect_conflicts

_start_time = datetime.now()

app = FastAPI(title="FRLc — Firewall Rule Language Compiler API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class RuleInput(BaseModel):
    rules: str

class PacketInput(BaseModel):
    protocol: str
    source: str
    destination: str
    port: int | None = None

@app.get("/")
def home():
    return {"message": "FRLc Firewall Rule Language Compiler API"}


@app.get("/health")
def health():
    rules  = firewall_service.get_rules()
    logs   = firewall_service.get_logs()
    uptime = int((datetime.now() - _start_time).total_seconds())
    h, rem = divmod(uptime, 3600)
    m, s   = divmod(rem, 60)
    allowed = sum(1 for l in logs if l["decision"] == "ALLOW")
    denied  = sum(1 for l in logs if l["decision"] == "DENY")
    return {
        "status":            "online",
        "uptime":            f"{h:02d}:{m:02d}:{s:02d}",
        "uptime_seconds":    uptime,
        "active_rules":      len(rules),
        "packets_evaluated": len(logs),
        "allowed":           allowed,
        "denied":            denied,
    }


@app.post("/compile")
def compile_rules(rule_input: RuleInput):
    try:
        rules     = firewall_service.compile_rules(rule_input.rules)
        shadows   = detect_shadow_rules(rules)
        conflicts = detect_conflicts(rules)
        allow_count = sum(1 for r in rules if r.action_str == "ALLOW")
        deny_count  = sum(1 for r in rules if r.action_str == "DENY")
        return {
            "status":      "success",
            "message":     "Rules compiled successfully",
            "rule_count":  len(rules),
            "allow_count": allow_count,
            "deny_count":  deny_count,
            "warnings":    shadows,
            "conflicts":   conflicts,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@app.get("/ast")
def get_ast():
    """Return the pretty-printed AST for the current ruleset."""
    return {"ast": firewall_service.get_ast_repr()}


@app.post("/simulate")
def simulate_packet(packet_input: PacketInput):
    try:
        start = time.time()
        decision, matched_rule = firewall_service.simulate_packet(
            packet_input.protocol,
            packet_input.source,
            packet_input.destination,
            packet_input.port
        )
        processing_time = (time.time() - start) * 1000

        db = SessionLocal()
        db.add(PacketLog(
            protocol=packet_input.protocol,
            source=packet_input.source,
            destination=packet_input.destination,
            port=packet_input.port,
            decision=decision
        ))
        db.commit()
        db.close()

        return {
            "packet":             dict(packet_input),
            "decision":           decision,
            "matched_rule":       str(matched_rule),
            "processing_time_ms": round(processing_time, 3),
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/logs")
def get_logs():
    logs = firewall_service.get_logs()
    result = []
    for log in logs:
        p = log["packet"]
        result.append({
            "time":         log.get("time", datetime.now().strftime("%H:%M:%S")),
            "protocol":     p.protocol,
            "source":       p.source,
            "destination":  p.destination,
            "port":         p.port,
            "decision":     log["decision"],
            "matched_rule": str(log["matched_rule"]) if log["matched_rule"] else "default-deny",
        })
    return result


@app.get("/stats")
def get_stats():
    return firewall_service.get_stats()


@app.get("/rules")
def get_rules():
    rules = firewall_service.get_rules()
    return {"rules": [str(r) for r in rules]}


@app.get("/iptables")
def get_iptables():
    """Backend 1: Generate Linux iptables commands."""
    rules = firewall_service.get_rules()
    return {"commands": convert_all_rules(rules)}


@app.get("/nftables")
def get_nftables():
    """Backend 2: Generate modern nftables ruleset."""
    rules = firewall_service.get_rules()
    return {
        "ruleset":   convert_to_nftables(rules),
        "rules":     convert_all_rules_nft(rules),
    }


@app.get("/analyze")
def analyze_rules():
    rules     = firewall_service.get_rules()
    shadows   = detect_shadow_rules(rules)
    conflicts = detect_conflicts(rules)
    return {
        "warnings":     shadows,
        "conflicts":    conflicts,
        "total_issues": len(shadows) + len(conflicts),
    }
