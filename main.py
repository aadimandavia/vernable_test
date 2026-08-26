
    base_dir = Path("/var/data").resolve()
    requested = (base_dir / filename).resolve()
    if base_dir not in requested.parents and requested != base_dir:
        raise HTTPException(status_code=400, detail="Invalid file path")
    return FileResponse(requested)