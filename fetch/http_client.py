import httpx

async def fetch_url(url: str):
    """
    Fetches the content of a URL.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(url, follow_redirects=True)
        response.raise_for_status()
        return response
