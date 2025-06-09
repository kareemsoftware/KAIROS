import pytest
from httpx import AsyncClient, Response, RequestError, HTTPStatusError, TimeoutException
from fastapi import HTTPException
import os
from unittest.mock import patch, AsyncMock

# Ensure the app can be imported
# Add llm_gateway/app to Python path for testing if necessary,
# or structure tests to be runnable with `python -m pytest` from project root.
# For simplicity here, assuming direct import works or PYTHONPATH is adjusted.
from app.main import app, OPENROUTER_API_KEY as APP_OPENROUTER_API_KEY # Import app and the key it uses

# Store original API key and set a test key
ORIGINAL_ENV_OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
TEST_OPENROUTER_API_KEY = "test_openrouter_api_key_for_llm_gateway" # Ensure this is what the app module sees

@pytest.fixture(scope="module", autouse=True)
def set_test_env_vars():
    # This fixture ensures that the environment variable used by the app module
    # is set for the duration of the tests in this module.
    os.environ["OPENROUTER_API_KEY"] = TEST_OPENROUTER_API_KEY
    # Update the app's global variable if it's already been read at import time
    # This is a bit of a hack due to how Python modules load globals.
    # A better solution might involve app factory pattern for FastAPI.
    app.OPENROUTER_API_KEY = TEST_OPENROUTER_API_KEY
    yield
    # Restore original environment variable after tests
    if ORIGINAL_ENV_OPENROUTER_API_KEY is None:
        del os.environ["OPENROUTER_API_KEY"]
    else:
        os.environ["OPENROUTER_API_KEY"] = ORIGINAL_ENV_OPENROUTER_API_KEY
    app.OPENROUTER_API_KEY = ORIGINAL_ENV_OPENROUTER_API_KEY # Restore app's global

@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_cognitive_task_direct_model_call(mock_post, client: AsyncClient):
    mock_post.return_value = Response(
        200,
        json={"id": "direct_call_id", "choices": [{"message": {"role": "assistant", "content": "Direct model response"}}]}
    )

    payload = {
        "prompt": "Test prompt for direct model",
        "model": "some/specific-model:free" # Bypass routing
    }
    response = await client.post("/v1/cognitive-task", json=payload)
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Direct model response"

    mock_post.assert_called_once()
    called_args, called_kwargs = mock_post.call_args
    assert called_kwargs["json"]["model"] == "some/specific-model:free"
    assert called_kwargs["json"]["messages"][-1]["content"] == "Test prompt for direct model"

@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_cognitive_task_routed_call_coding(mock_post, client: AsyncClient):
    # Simulate two calls: first to router, second to specialized model
    mock_post.side_effect = [
        Response(200, json={"id": "router_id", "choices": [{"message": {"role": "assistant", "content": "coding"}}]}), # Router classifies as 'coding'
        Response(200, json={"id": "specialized_id", "choices": [{"message": {"role": "assistant", "content": "Specialized coding response"}}]}) # Specialized model response
    ]

    payload = {"prompt": "Write a python script"} # No model specified, should trigger routing
    response = await client.post("/v1/cognitive-task", json=payload)

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Specialized coding response"

    assert mock_post.call_count == 2

    # Check router call
    router_call_args, router_call_kwargs = mock_post.call_args_list[0]
    assert router_call_kwargs["json"]["model"] == "mistralai/mistral-7b-instruct:free" # Router model
    assert "Classify the following user request" in router_call_kwargs["json"]["messages"][-1]["content"]
    assert "Write a python script" in router_call_kwargs["json"]["messages"][-1]["content"]

    # Check specialized call
    specialized_call_args, specialized_call_kwargs = mock_post.call_args_list[1]
    assert specialized_call_kwargs["json"]["model"] == "qwen/qwen-2-7b-instruct:free" # Specialized coding model
    assert specialized_call_kwargs["json"]["messages"][-1]["content"] == "Write a python script"


@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_cognitive_task_router_fails_default_model(mock_post, client: AsyncClient):
    # Router LLM fails, should default to general model
    mock_post.side_effect = [
        HTTPStatusError("Router LLM failed", request=AsyncMock(), response=Response(500, text="Router error")), # Router call fails
        Response(200, json={"id": "default_id", "choices": [{"message": {"role": "assistant", "content": "Default model response after router failure"}}]}) # Default model response
    ]

    payload = {"prompt": "A general question"}
    response = await client.post("/v1/cognitive-task", json=payload)
    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Default model response after router failure"

    assert mock_post.call_count == 2
    # Specialized call should be to the default model
    specialized_call_args, specialized_call_kwargs = mock_post.call_args_list[1]
    assert specialized_call_kwargs["json"]["model"] == "meta-llama/llama-3-8b-instruct:free" # Default model

@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_cognitive_task_specialized_llm_fails(mock_post, client: AsyncClient):
    # Router succeeds, but specialized LLM call fails
    mock_post.side_effect = [
        Response(200, json={"id": "router_id", "choices": [{"message": {"role": "assistant", "content": "reasoning"}}]}),
        HTTPStatusError("Specialized LLM failed", request=AsyncMock(), response=Response(503, json={"error": "Service unavailable"}))
    ]

    payload = {"prompt": "A reasoning question"}
    response = await client.post("/v1/cognitive-task", json=payload)
    assert response.status_code == 503 # Error from specialized LLM should be propagated
    assert "Service unavailable" in response.json()["detail"]["error"]

@pytest.mark.asyncio
async def test_missing_prompt(client: AsyncClient):
    response = await client.post("/v1/cognitive-task", json={}) # Empty payload
    assert response.status_code == 400
    assert "Missing 'prompt' in payload" in response.json()["detail"]

    response = await client.post("/v1/cognitive-task", json={"prompt": ""}) # Empty prompt
    assert response.status_code == 400
    assert "Missing 'prompt' in payload" in response.json()["detail"] # Corrected, should be caught by the `if not user_prompt`

@pytest.mark.asyncio
@patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}) # Temporarily unset API key for this test
@patch("app.main.OPENROUTER_API_KEY", "") # Also patch the global in the module
async def test_no_api_key_configured(client: AsyncClient):
    # This test requires careful handling of how the API key is accessed by the app.
    # If it's read at module import, this test might need to be in a separate file
    # or use more advanced patching/reloading.
    # The fixture `set_test_env_vars` tries to handle this, but let's double-check.

    # Re-patch the app's global OPENROUTER_API_KEY for this specific test case
    with patch("app.main.OPENROUTER_API_KEY", ""):
        payload = {"prompt": "Test with no API key", "model": "some/model"}
        response = await client.post("/v1/cognitive-task", json=payload)
        assert response.status_code == 500
        assert "OPENROUTER_API_KEY not configured" in response.json()["detail"]

@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_openrouter_timeout(mock_post, client: AsyncClient):
    mock_post.side_effect = TimeoutException("Request timed out", request=AsyncMock())
    payload = {"prompt": "Test timeout", "model": "some/model"}
    response = await client.post("/v1/cognitive-task", json=payload)
    assert response.status_code == 504 # Gateway Timeout
    assert "Request to OpenRouter timed out" in response.json()["detail"]

@pytest.mark.asyncio
@patch("app.main.httpx.AsyncClient.post", new_callable=AsyncMock)
async def test_openrouter_request_error(mock_post, client: AsyncClient):
    mock_post.side_effect = RequestError("Connection failed", request=AsyncMock())
    payload = {"prompt": "Test connection error", "model": "some/model"}
    response = await client.post("/v1/cognitive-task", json=payload)
    assert response.status_code == 503 # Service Unavailable
    assert "Error connecting to OpenRouter" in response.json()["detail"]
