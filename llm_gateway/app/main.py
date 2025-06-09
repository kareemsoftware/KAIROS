from fastapi import FastAPI, HTTPException, Body
import httpx
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO) # Sets up basic configuration for logging
logger = logging.getLogger(__name__) # Get a logger instance for this module

app = FastAPI(title="LLM Gateway")

# --- Environment Variables & Configuration ---
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY") # API key for OpenRouter services
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions" # API endpoint for OpenRouter

# --- Model Configuration ---
# Defines the model used for routing user prompts to specialized models.
ROUTER_MODEL = "mistralai/mistral-7b-instruct:free" # A small, fast model suitable for classification tasks.

# Maps classified categories to specific, specialized LLM models.
# These models are chosen based on their strengths in handling certain types of prompts.
MODEL_SPECIALIZATION_MAP = {
    "reasoning": "microsoft/phi-3-medium-128k-instruct:free", # Good for logical deduction and problem-solving.
    "coding": "qwen/qwen-2-7b-instruct:free", # Specialized for code generation and programming-related questions.
    "visual": "internlm/internlm-xcomposer2-vl-7b:free", # A Vision-Language model; assumes text prompt for visual task for now.
    "strategic": "google/gemini-flash-1.5:free", # Suited for planning and strategic thinking.
    "general": "meta-llama/llama-3-8b-instruct:free", # A capable general-purpose model.
    "default": "meta-llama/llama-3-8b-instruct:free" # Fallback model if classification is unclear or fails.
}

async def make_openrouter_request(model: str, prompt: str, max_tokens: int = None, temperature: float = None, system_prompt: str = None):
    """
    Helper function to make a POST request to the OpenRouter API.

    Args:
        model: The model identifier to use for the request.
        prompt: The user's prompt.
        max_tokens: Optional maximum number of tokens for the response.
        temperature: Optional temperature for controlling response randomness.
        system_prompt: Optional system message to guide the LLM's behavior.

    Returns:
        The JSON response from OpenRouter.

    Raises:
        HTTPException: If the API key is not configured or if there are errors during the API call.
    """
    if not OPENROUTER_API_KEY:
        logger.error("OPENROUTER_API_KEY not configured")
        raise HTTPException(status_code=500, detail="OPENROUTER_API_KEY not configured")

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}", # API key for authentication
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost", # Optional: Some models prefer this for tracking or policy reasons.
        "X-Title": "KAIROS LLM Gateway" # Optional: Custom title for identifying the application.
    }

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    data = {
        "model": model,
        "messages": messages
    }

    # Add optional parameters to the request payload if provided
    if max_tokens is not None:
        data["max_tokens"] = max_tokens
    if temperature is not None:
        data["temperature"] = temperature

    logger.info(f"Sending request to OpenRouter. Model: {model}, Prompt Length: {len(prompt)}, System Prompt Used: {'Yes' if system_prompt else 'No'}")

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(OPENROUTER_API_URL, headers=headers, json=data, timeout=180.0) # Increased timeout for potentially long LLM responses
            response.raise_for_status() # Raise an exception for HTTP error codes (4xx or 5xx)
            logger.info(f"Received response from OpenRouter. Model: {model}, Status: {response.status_code}")
            return response.json()
        except httpx.HTTPStatusError as e:
            # Handle HTTP errors from OpenRouter
            error_detail = f"Error from OpenRouter: {e.response.status_code}"
            try:
                error_body = e.response.json() # Try to parse error body as JSON
                error_detail += f" - {error_body}"
                logger.error(f"HTTPStatusError from OpenRouter for model {model}: {e.response.status_code} - Body: {error_body}")
            except Exception: # Fallback if error body is not JSON
                error_detail += f" - {e.response.text}"
                logger.error(f"HTTPStatusError from OpenRouter for model {model}: {e.response.status_code} - Text: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail=error_detail)
        except httpx.TimeoutException:
            # Handle timeout errors when calling OpenRouter
            logger.error(f"Request to OpenRouter timed out for model {model}")
            raise HTTPException(status_code=504, detail=f"Request to OpenRouter timed out for model {model}")
        except httpx.RequestError as e:
            # Handle other request errors (e.g., network issues)
            logger.error(f"Error connecting to OpenRouter for model {model}: {str(e)}")
            raise HTTPException(status_code=503, detail=f"Error connecting to OpenRouter: {str(e)}")


@app.post("/v1/cognitive-task")
async def cognitive_task_proxy(payload: dict = Body(...)):
    """
    Main endpoint for processing user prompts.
    It can either use a user-specified model or route the prompt to a specialized model
    based on classification by a router LLM.
    """
    user_prompt = payload.get("prompt")
    if not user_prompt: # Ensure a prompt is provided
        logger.warning("Cognitive task request received without a prompt.")
        raise HTTPException(status_code=400, detail="Missing 'prompt' in payload")

    forced_model = payload.get("model") # User can override routing by specifying a model directly
    max_tokens = payload.get("max_tokens") # Optional: Max tokens for the response
    temperature = payload.get("temperature") # Optional: Temperature for the response

    target_model = None # The model that will ultimately process the prompt

    if forced_model:
        # If a model is specified in the payload, bypass routing logic.
        logger.info(f"User specified model override: {forced_model}. Bypassing router LLM.")
        target_model = forced_model
    else:
        # --- Routing Logic ---
        # 1. Construct prompt for the Router LLM.
        # This prompt asks the Router LLM to classify the user's request.
        router_prompt = f"Classify the following user request into one of these categories: [reasoning, coding, visual, strategic, general]. Respond with only the single category word. Request: {user_prompt}"
        logger.info(f"Routing user prompt (first 100 chars): '{router_prompt[:100]}...'")

        try:
            # Call the Router LLM.
            router_response_json = await make_openrouter_request(
                model=ROUTER_MODEL,
                prompt=router_prompt,
                max_tokens=20, # Expecting a short, single-word response.
                temperature=0.1 # Low temperature for more deterministic classification.
            )

            # Process the Router LLM's response.
            if router_response_json and router_response_json.get("choices") and router_response_json["choices"][0].get("message"):
                classified_category_full = router_response_json["choices"][0]["message"].get("content", "").strip().lower()
                # Extract the first word which should be the category. Handles cases where LLM might add minor extra text.
                classified_category = classified_category_full.split()[0] if classified_category_full else "general"
                logger.info(f"Router LLM classified prompt as: '{classified_category}' (Full response: '{classified_category_full}')")

                # Select the specialized model based on the classification.
                target_model = MODEL_SPECIALIZATION_MAP.get(classified_category, MODEL_SPECIALIZATION_MAP["default"])
                logger.info(f"Selected specialized model: {target_model} based on classification '{classified_category}'")
            else:
                # If the router's response is unexpected, default to a general model.
                logger.warning("Router LLM did not return a valid classification. Defaulting to general model.")
                target_model = MODEL_SPECIALIZATION_MAP["default"]
        except HTTPException as e:
            # If the router call itself fails (e.g., API error), log and default.
            logger.error(f"HTTPException during router LLM call: {e.detail}. Defaulting to general model.")
            target_model = MODEL_SPECIALIZATION_MAP["default"]
        except Exception as e:
            # Catch any other unexpected errors during routing and default.
            logger.error(f"Unexpected error during router LLM call: {str(e)}. Defaulting to general model.")
            target_model = MODEL_SPECIALIZATION_MAP["default"]

    # 2. Call Specialized LLM (or the user-forced model)
    if not target_model: # Safeguard: Should always be set by this point.
        logger.error("Target model could not be determined (this indicates a flaw in the logic). Defaulting to general model.")
        target_model = MODEL_SPECIALIZATION_MAP["default"]

    logger.info(f"Proxying original prompt to target model: {target_model}. Prompt length: {len(user_prompt)}.")

    # --- System Prompts for Specialized Models ---
    # These system prompts can help guide the specialized LLMs to provide better responses.
    # For visual tasks, the prompt might need to be structured differently if it includes image data.
    # The current setup assumes the prompt for a 'visual' task is a text description.
    # If actual image data needs to be passed, this part would need modification to handle multi-modal input.

    system_prompt_specialized = "You are a specialized AI assistant. Provide a detailed and helpful response to the user's request based on your area of expertise."
    if target_model == MODEL_SPECIALIZATION_MAP["coding"]:
        system_prompt_specialized = "You are an expert coding assistant. Provide accurate and efficient code solutions, explanations, or debugging help. If generating code, ensure it is well-commented and follows best practices."
    elif target_model == MODEL_SPECIALIZATION_MAP["reasoning"]:
        system_prompt_specialized = "You are an expert reasoning and problem-solving assistant. Analyze the request carefully, break down complex problems, and provide logical, step-by-step explanations or solutions."
    # TODO: Add more tailored system prompts for other categories (visual, strategic) if beneficial.

    # Make the final call to the selected (or forced) OpenRouter model.
    return await make_openrouter_request(
        model=target_model,
        prompt=user_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        system_prompt=system_prompt_specialized
    )

@app.get("/")
async def read_root_gateway():
    return {"message": "LLM Gateway is running with Smart Routing"}

# Example command to run this FastAPI application using Uvicorn:
# OPENROUTER_API_KEY="your_key_here" uvicorn main:app --reload --port 8001
    "coding": "qwen/qwen-2-7b-instruct:free", # Smaller Qwen code model
    "visual": "internlm/internlm-xcomposer2-vl-7b:free", # VL model, assumes text prompt for visual task for now
    "strategic": "google/gemini-flash-1.5:free",
    "general": "meta-llama/llama-3-8b-instruct:free",
    "default": "meta-llama/llama-3-8b-instruct:free"
}

async def make_openrouter_request(model: str, prompt: str, max_tokens: int = None, temperature: float = None, system_prompt: str = None):
    if not OPENROUTER_API_KEY:
        logger.error("OPENROUTER_API_KEY not configured")
        raise HTTPException(status_code=500, detail="OPENROUTER_API_KEY not configured")

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost", # Optional, some models prefer it
        "X-Title": "KAIROS LLM Gateway" # Optional
    }

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    data = {
        "model": model,
        "messages": messages
    }

    if max_tokens is not None:
        data["max_tokens"] = max_tokens
    if temperature is not None:
        data["temperature"] = temperature

    logger.info(f"Sending request to OpenRouter. Model: {model}, Prompt Length: {len(prompt)}")

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(OPENROUTER_API_URL, headers=headers, json=data, timeout=180.0) # Increased timeout
            response.raise_for_status()
            logger.info(f"Received response from OpenRouter. Model: {model}, Status: {response.status_code}")
            return response.json()
        except httpx.HTTPStatusError as e:
            error_detail = f"Error from OpenRouter: {e.response.status_code}"
            try:
                error_body = e.response.json()
                error_detail += f" - {error_body}"
                logger.error(f"HTTPStatusError from OpenRouter for model {model}: {e.response.status_code} - Body: {error_body}")
            except Exception:
                error_detail += f" - {e.response.text}"
                logger.error(f"HTTPStatusError from OpenRouter for model {model}: {e.response.status_code} - Text: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail=error_detail)
        except httpx.TimeoutException:
            logger.error(f"Request to OpenRouter timed out for model {model}")
            raise HTTPException(status_code=504, detail=f"Request to OpenRouter timed out for model {model}")
        except httpx.RequestError as e:
            logger.error(f"Error connecting to OpenRouter for model {model}: {str(e)}")
            raise HTTPException(status_code=503, detail=f"Error connecting to OpenRouter: {str(e)}")


@app.post("/v1/cognitive-task") # Changed endpoint name as per user doc
async def cognitive_task_proxy(payload: dict = Body(...)):
    user_prompt = payload.get("prompt")
    if not user_prompt:
        raise HTTPException(status_code=400, detail="Missing 'prompt' in payload")

    forced_model = payload.get("model") # User can override routing by specifying a model
    max_tokens = payload.get("max_tokens")
    temperature = payload.get("temperature")

    target_model = None

    if forced_model:
        logger.info(f"User specified model override: {forced_model}")
        target_model = forced_model
    else:
        # 1. Call Router LLM
        router_prompt = f"Classify the following user request into one of these categories: [reasoning, coding, visual, strategic, general]. Respond with only the single category word. Request: {user_prompt}"
        logger.info(f"Routing prompt (first 100 chars): {router_prompt[:100]}...")

        try:
            router_response_json = await make_openrouter_request(
                model=ROUTER_MODEL,
                prompt=router_prompt,
                max_tokens=20, # Small response expected
                temperature=0.1 # Low temperature for classification
            )

            if router_response_json and router_response_json.get("choices") and router_response_json["choices"][0].get("message"):
                classified_category_full = router_response_json["choices"][0]["message"].get("content", "").strip().lower()
                # Extract the first word which should be the category
                classified_category = classified_category_full.split()[0] if classified_category_full else "general"
                logger.info(f"Router LLM classified prompt as: '{classified_category}' (Full response: '{classified_category_full}')")

                target_model = MODEL_SPECIALIZATION_MAP.get(classified_category, MODEL_SPECIALIZATION_MAP["default"])
                logger.info(f"Selected specialized model: {target_model} based on classification '{classified_category}'")
            else:
                logger.warning("Router LLM did not return a valid classification. Defaulting model.")
                target_model = MODEL_SPECIALIZATION_MAP["default"]
        except HTTPException as e:
            logger.error(f"HTTPException during router LLM call: {e.detail}. Defaulting model.")
            target_model = MODEL_SPECIALIZATION_MAP["default"]
        except Exception as e:
            logger.error(f"Unexpected error during router LLM call: {str(e)}. Defaulting model.")
            target_model = MODEL_SPECIALIZATION_MAP["default"]

    # 2. Call Specialized LLM
    if not target_model: # Should be set by now, but as a safeguard
        logger.error("Target model could not be determined. This should not happen.")
        target_model = MODEL_SPECIALIZATION_MAP["default"]

    logger.info(f"Proxying original prompt to specialized model: {target_model}")
    # For visual tasks, the prompt might need to be structured differently if it includes image data.
    # The current setup assumes the prompt for a 'visual' task is a text description.
    # If actual image data needs to be passed, this part would need modification to handle multi-modal input.

    system_prompt_specialized = "You are a specialized AI assistant. Provide a detailed and helpful response to the user's request based on your area of expertise."
    if target_model == MODEL_SPECIALIZATION_MAP["coding"]:
        system_prompt_specialized = "You are an expert coding assistant. Provide accurate and efficient code solutions, explanations, or debugging help. If generating code, ensure it is well-commented and follows best practices."
    elif target_model == MODEL_SPECIALIZATION_MAP["reasoning"]:
        system_prompt_specialized = "You are an expert reasoning and problem-solving assistant. Analyze the request carefully, break down complex problems, and provide logical, step-by-step explanations or solutions."
    # Add more system prompts for other categories if needed.

    return await make_openrouter_request(
        model=target_model,
        prompt=user_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        system_prompt=system_prompt_specialized
    )

@app.get("/")
async def read_root_gateway():
    return {"message": "LLM Gateway is running with Smart Routing"}

# To run this gateway (example):
# OPENROUTER_API_KEY="your_key_here" uvicorn main:app --reload --port 8001
