from fastapi import HTTPException


def raise_http_exception(status, body, headers):
    raise HTTPException(
        status_code=status,
        detail=body,
        headers=dict(headers)
    )
