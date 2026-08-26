@app.get("/files")
def get_file(filename: str):
    # INTENTIONALLY VULNERABLE
    file_path = BASE_DIR / filename

    base_dir = Path("/var/data").resolve()
    requested = (base_dir / filename).resolve()
    if base_dir not in requested.parents and requested != base_dir:
        raise HTTPException(status_code=400, detail="Invalid file path")
    return FileResponse(requested)