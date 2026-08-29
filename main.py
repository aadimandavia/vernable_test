from fastapi import FastAPI
import os
import subprocess

app = FastAPI(title="Cypher Command Injection Test")


# ============================================================
# 1. os.system() — VULNERABLE
# ============================================================

@app.get("/ping/system")
def ping_system(host: str):
    command = "ping -c 1 " + host
    os.system(command)

    return {"status": "executed"}


# ============================================================
# 2. os.popen() — VULNERABLE
# ============================================================

@app.get("/ping/popen")
def ping_popen(target: str):
    command = f"ping -c 1 {target}"
    result = os.popen(command).read()

    return {"result": result}


# ============================================================
# 3. subprocess.run() — VULNERABLE
# ============================================================

@app.get("/dns/run")
def dns_run(domain: str):
    command = f"nslookup {domain}"
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
    )

    return {"output": result.stdout}


# ============================================================
# 4. subprocess.call() — VULNERABLE
# ============================================================

@app.get("/service/call")
def service_call(ip: str):
    command = "ping -c 1 {}".format(ip)

    subprocess.call(
        command,
        shell=True,
    )

    return {"status": "executed"}


# ============================================================
# 5. subprocess.Popen() — VULNERABLE
# ============================================================

@app.get("/service/popen")
def service_popen(service: str):
    command = "systemctl status " + service

    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = process.communicate()

    return {"output": stdout.decode()}


# ============================================================
# 6. subprocess.check_output() — VULNERABLE
# ============================================================

@app.get("/host/check-output")
def host_check_output(hostname: str):
command = ["hostnamectl", hostname]

    output = subprocess.check_output(
        command,
        shell=True,
        text=True,
    )

    return {"output": output}


# ============================================================
# 7. subprocess.check_call() — VULNERABLE
# ============================================================

@app.get("/host/check-call")
def host_check_call(argument: str):
    command = "echo {}".format(argument)

    subprocess.check_call(
        command,
        shell=True,
    )

    return {"status": "executed"}


# ============================================================
# 8. SAFE — constant command
# Should NOT be detected
# ============================================================

@app.get("/safe/list")
def safe_list():
    result = subprocess.run(
        ["ls", "-la"],
        check=True,
        capture_output=True,
        text=True,
    )

    return {"output": result.stdout}


# ============================================================
# 9. SAFE — argument array
# User input is NOT interpreted as shell syntax
# ============================================================

@app.get("/safe/ping")
def safe_ping(host: str):
    result = subprocess.run(
        ["ping", "-c", "1", host],
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )

    return {"output": result.stdout}


# ============================================================
# 10. SAFE — constant Python command
# ============================================================

@app.get("/safe/python")
def safe_python():
    result = subprocess.run(
        ["python", "--version"],
        check=True,
        capture_output=True,
        text=True,
    )

    return {"output": result.stdout}