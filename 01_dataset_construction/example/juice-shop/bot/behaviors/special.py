import asyncio

from bs4 import BeautifulSoup

from providers import http


async def get_scripts_links(html: str) -> None:
    soup = BeautifulSoup(html, "html.parser")

    # Collect the URLs of all JavaScript assets.
    js_urls = [script["src"] for script in soup.find_all("script", src=True)]

    # Collect the URLs of all stylesheet assets.
    css_urls = [link["href"] for link in soup.find_all("link")]

    tasks = [http.client.get(url) for url in js_urls + css_urls]
    await asyncio.gather(*tasks)


async def init_app() -> None:
    res = await http.client.get("/")
    html = res.text
    await get_scripts_links(html)
    await asyncio.gather(
        http.get_rest("/rest/admin/application-configuration"),
        http.get_rest("/rest/admin/application-version"),
        http.get_rest("/rest/languages"),
        http.get_rest("/rest/user/whoami"),
    )
    await http.get_rest("/rest/products/search?q=")
