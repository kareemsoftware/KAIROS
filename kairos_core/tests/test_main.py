import pytest
from httpx import AsyncClient, Response, RequestError, HTTPStatusError
from fastapi import HTTPException
from unittest.mock import patch, AsyncMock, MagicMock

# Assuming the app can be imported. Adjust if necessary for your project structure.
from app.main import app
# We need to mock the Celery task object's .delay method
# If tasks are in app.tasks, and placeholder_wordpress_scan is an object there:
import app.tasks

@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.get", new_callable=AsyncMock) # Mocks GET for target URL
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock) # Mocks POST to LLM Gateway
@patch("app.tasks.placeholder_wordpress_scan.delay", new_callable=MagicMock) # Mocks Celery task's delay
async def test_create_scan_success_no_wordpress(
    mock_celery_delay, mock_llm_post, mock_target_get, client: AsyncClient
):
    # --- Mock Setup ---
    # Mock fetching target URL
    mock_target_get.return_value = Response(
        200,
        text="<html><head><title>Test Site</title></head><body>Hello</body></html>",
        headers={"content-type": "text/html; charset=utf-8", "Server": "TestServer/1.0"}
    )

    # Mock LLM Gateway response (hypothesis does NOT contain 'wordpress')
    mock_llm_post.return_value = Response(
        200,
        json={"id": "llm_id", "choices": [{"message": {"role": "assistant", "content": "This is a generic blog."}}]}
    )

    # --- API Call ---
    payload = {"target_url": "http://example.com"}
    response = await client.post("/scan", json=payload)

    # --- Assertions ---
    assert response.status_code == 200
    data = response.json()

    assert data["target_final_url"] == "http://example.com" # Assuming no redirect from mock
    assert data["status_code"] == 200
    assert data["title"] == "Test Site"
    assert "TestServer/1.0" in data["headers"]["server"]
    assert data["whois_simulated"]["domain_name"] == "example.com"
    assert data["hypothesis_llm"] == "This is a generic blog."
    assert "No Celery task dispatched based on hypothesis." in data["celery_task_dispatch_status"] or \
           "Hypothesis did not indicate WordPress" in data["celery_task_dispatch_status"]

    mock_target_get.assert_called_once_with("http://example.com", timeout=30.0, follow_redirects=True)

    mock_llm_post.assert_called_once()
    llm_call_args, llm_call_kwargs = mock_llm_post.call_args
    assert llm_call_kwargs["json"]["prompt"].startswith("Based on the following website data")
    assert "http://example.com" in llm_call_kwargs["json"]["prompt"]
    assert llm_call_kwargs["json"]["model"] == "meta-llama/llama-3-8b-instruct:free"

    mock_celery_delay.assert_not_called() # WordPress not in hypothesis

@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.get", new_callable=AsyncMock)
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock)
@patch.object(app.tasks.placeholder_wordpress_scan, 'delay') # More specific patch for the task object
async def test_create_scan_success_with_wordpress_task(
    mock_celery_delay, mock_llm_post, mock_target_get, client: AsyncClient
):
    # --- Mock Setup ---
    mock_target_get.return_value = Response(
        200,
        text="<html><title>WP Site</title></html>",
        headers={"content-type": "text/html", "Server": "Apache"}
    )
    mock_llm_post.return_value = Response(
        200,
        json={"id": "llm_wp_id", "choices": [{"message": {"role": "assistant", "content": "This is likely a WordPress site."}}]}
    )
    # Mock the return value of .delay() to include a task_id, like Celery would
    mock_celery_delay.return_value = AsyncMock(id="test-task-id-123")


    # --- API Call ---
    payload = {"target_url": "http://wordpress-example.com"}
    response = await client.post("/scan", json=payload)

    # --- Assertions ---
    assert response.status_code == 200
    data = response.json()

    assert data["hypothesis_llm"] == "This is likely a WordPress site."
    assert "Dispatched placeholder_wordpress_scan task. ID: test-task-id-123" in data["celery_task_dispatch_status"]

    mock_target_get.assert_called_once_with("http://wordpress-example.com", timeout=30.0, follow_redirects=True)
    mock_llm_post.assert_called_once()
    mock_celery_delay.assert_called_once_with("http://wordpress-example.com") # Assuming final URL is the same


@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.get", new_callable=AsyncMock)
async def test_create_scan_target_fetch_fails(mock_target_get, client: AsyncClient):
    mock_target_get.side_effect = HTTPStatusError(
        "Target down", request=AsyncMock(), response=Response(500, text="Server Error")
    )

    payload = {"target_url": "http://broken-site.com"}
    response = await client.post("/scan", json=payload)

    assert response.status_code == 200 # The endpoint itself doesn't fail, it reports the error in the body
    data = response.json()
    assert data["error"] == "Failed to fetch http://broken-site.com"
    assert data["details"]["error_fetching_headers"] == "HTTP 500"

@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.get", new_callable=AsyncMock)
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_create_scan_llm_gateway_fails(mock_llm_post, mock_target_get, client: AsyncClient):
    mock_target_get.return_value = Response(200, text="<title>OK</title>", headers={"content-type": "text/html"})
    mock_llm_post.side_effect = HTTPStatusError(
        "LLM Gateway down", request=AsyncMock(), response=Response(503, json={"detail": "LLM Service Unavailable"})
    )

    payload = {"target_url": "http://example.com"}
    response = await client.post("/scan", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert "Failed to get hypothesis from LLM Gateway" in data["hypothesis_llm"]
    assert "LLM Service Unavailable" in data["hypothesis_llm"]
    assert "Could not dispatch Celery task due to LLM Gateway error" in data["celery_task_dispatch_status"]


@pytest.mark.asyncio
async def test_create_scan_missing_target_url(client: AsyncClient):
    response = await client.post("/scan", json={}) # Empty payload
    assert response.status_code == 400
    assert "target_url is required" in response.json()["detail"]

    response = await client.post("/scan", json={"target_url": ""}) # Empty target_url
    assert response.status_code == 400
    assert "target_url is required" in response.json()["detail"]
