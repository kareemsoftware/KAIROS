from fastapi import FastAPI, HTTPException, Body
import httpx
import logging
import json

# Celery specific imports
from app.celery_app import celery_app # Import celery_app instance
from app.tasks import placeholder_wordpress_scan # Import specific task

# Configure logging
logging.basicConfig(level=logging.INFO) # Basic logging configuration
logger = logging.getLogger(__name__) # Logger instance for this module

app = FastAPI(title="KAIROS Core")

# URL for the LLM Gateway service, used for making requests for hypothesis generation.
# Assumes 'llm-gateway' is the service name in the Docker network.
LLM_GATEWAY_URL = "http://llm-gateway:8000/v1/cognitive-task"

@app.get("/")
async def read_root():
    """Root endpoint to confirm the KAIROS Core service is running."""
    return {"message": "KAIROS Core is running"}

@app.post("/scan")
async def create_scan(payload: dict = Body(...)):
    """
    Endpoint to initiate a scan for a target URL.
    It gathers basic information, generates a hypothesis using the LLM Gateway,
    and potentially dispatches a Celery task based on the hypothesis.
    """
    target_url = payload.get("target_url")
    if not target_url:
        logger.warning("Scan request received without a target_url in payload.")
        raise HTTPException(status_code=400, detail="target_url is required in payload")

    logger.info(f"Scan initiated for target URL: {target_url}")

    # Initialize dictionaries and variables to store scan results
    gathered_data = {} # Stores data collected about the target
    hypothesis = "Not generated" # Stores the hypothesis from the LLM
    celery_task_info = "No Celery task dispatched based on hypothesis." # Info about any dispatched Celery task

    async with httpx.AsyncClient() as client:
        # --- Step 1: Basic Information Gathering (Headers, Title) ---
        try:
            logger.info(f"Attempting to fetch information from {target_url}")
            # Make GET request to the target URL, follow redirects, set a timeout.
            response = await client.get(target_url, timeout=30.0, follow_redirects=True)
            response.raise_for_status() # Raise an exception for HTTP error codes (4xx or 5xx)

            # Store key information from the response
            gathered_data["target_final_url"] = str(response.url) # Final URL after redirects
            gathered_data["status_code"] = response.status_code
            gathered_data["headers"] = dict(response.headers) # Store response headers (logging full headers is avoided later)

            # Basic title extraction if content is HTML.
            # Note: This is a naive implementation. A more robust solution would use a proper HTML parser.
            if "text/html" in response.headers.get("content-type", "").lower():
                try:
                    html_content = response.text # Full HTML content is NOT logged.
                    title_start = html_content.lower().find("<title>")
                    title_end = html_content.lower().find("</title>")
                    if title_start != -1 and title_end != -1:
                        gathered_data["title"] = html_content[title_start + len("<title>"):title_end].strip()
                    else:
                        gathered_data["title"] = "N/A (Title tag not found)"
                except Exception as e_title: # Catch potential errors during string manipulation
                    logger.warning(f"Could not extract title for {target_url} despite text/html content type: {str(e_title)}")
                    gathered_data["title"] = "Error extracting title"
            else:
                gathered_data["title"] = "N/A (Content-Type is not text/html)"

            logger.info(f"Successfully fetched data from {gathered_data['target_final_url']} (Status: {response.status_code}). Title: '{gathered_data.get('title', 'N/A')}'")
        except httpx.HTTPStatusError as e:
            # Handle HTTP errors when trying to reach the target URL
            logger.error(f"HTTP error while fetching {target_url}: Status {e.response.status_code}. Response (first 100 chars): {e.response.text[:100]}")
            gathered_data["error_fetching_target"] = f"HTTP {e.response.status_code}: {e.response.text[:100]}" # Store a snippet of the error
            # Return a response indicating failure to fetch the target, as further scanning is not possible.
            return {"error": f"Failed to fetch {target_url}. The server returned an error.", "details": gathered_data}
        except httpx.RequestError as e:
            # Handle other request errors (e.g., network issues, DNS failure)
            logger.error(f"Request error while fetching {target_url}: {str(e)}")
            gathered_data["error_fetching_target"] = f"RequestError: {str(e)}"
            # Return a response indicating failure to connect to the target.
            return {"error": f"Failed to connect to {target_url}. Check the URL or network connectivity.", "details": gathered_data}

        # --- Step 2: WHOIS Information (Simulated) ---
        # In a real application, this would involve a proper WHOIS lookup.
        # For now, it's simulated using the domain name extracted from the target URL.
        current_url_for_whois = gathered_data.get('target_final_url', target_url)
        logger.info(f"Simulating WHOIS lookup for the domain of {current_url_for_whois}")
        try:
            # Basic domain extraction (can be improved for robustness)
            domain_to_simulate = current_url_for_whois.split("://")[-1].split("/")[0].split("?")[0]
        except IndexError: # Handle potential errors if URL format is unexpected
            domain_to_simulate = "unknown.domain"
            logger.warning(f"Could not reliably parse domain from {current_url_for_whois} for WHOIS simulation. Using '{domain_to_simulate}'.")
        gathered_data["whois_simulated"] = {
            "domain_name": domain_to_simulate,
            "registrar": "Simulated KAIROS Registrar",
            "creation_date": "2023-01-01T00:00:00Z",
            "emails": ["abuse@simulated-registrar.com", "admin@simulated-registrar.com"]
        }
        logger.info(f"WHOIS data simulated for {domain_to_simulate}")

        # 3. Hypothesis Generation
        try:
            info_summary_for_llm = {
                "url": gathered_data.get("target_final_url", target_url),
                "status": gathered_data.get("status_code"),
                "title": gathered_data.get("title", "N/A"),
                "server_header": gathered_data.get("headers", {}).get("server", gathered_data.get("headers", {}).get("Server")),
                "content_type_header": gathered_data.get("headers", {}).get("content-type", gathered_data.get("headers", {}).get("Content-Type")),
                "whois_registrar": gathered_data.get("whois_simulated", {}).get("registrar")
            }
            info_summary_for_llm_cleaned = {k: v for k, v in info_summary_for_llm.items() if v is not None} # Remove keys with None values for a cleaner prompt

            # Convert the summary dictionary to a JSON string for inclusion in the prompt.
            # Using indent for readability if the prompt were to be manually inspected (it's logged truncated).
            info_summary_str = json.dumps(info_summary_for_llm_cleaned, indent=2)

            llm_prompt = (
                "Based on the following website data, provide a brief, one-sentence hypothesis about the "
                "likely nature or primary technology of this website (e.g., 'This appears to be a blog', "
                "'This is likely an e-commerce site on Shopify', 'This might be a corporate page using WordPress'). "
                f"Data:\n{info_summary_str}"
            )

            # Log only a part of the prompt to avoid logging potentially sensitive summarized data from the website.
            logger.info(f"Sending prompt to LLM Gateway for hypothesis generation. Target: {current_url_for_whois}. Prompt (first 100 chars): {llm_prompt[:100]}...")

            # Payload for the LLM Gateway request
            llm_payload = {
                "prompt": llm_prompt,
                "model": "meta-llama/llama-3-8b-instruct:free", # Specify a general model for this system call
                "max_tokens": 100, # Limit response length for the hypothesis
                "temperature": 0.5 # Moderate temperature for some creativity but still factual
            }

            # Make the POST request to the LLM Gateway
            llm_response = await client.post(LLM_GATEWAY_URL, json=llm_payload, timeout=60.0)
            llm_response.raise_for_status() # Raise an exception for HTTP error codes
            llm_data = llm_response.json()

            # Extract hypothesis from LLM response
            if llm_data.get("choices") and llm_data["choices"][0].get("message"):
                hypothesis = llm_data["choices"][0]["message"].get("content", "Could not extract hypothesis from LLM response.").strip()
                logger.info(f"LLM generated hypothesis for {current_url_for_whois}: '{hypothesis}'") # Log the hypothesis itself as it's usually short and general.

                # --- Step 4: Dispatch Celery Task based on Hypothesis ---
                # Example: If hypothesis suggests WordPress, dispatch a specific scan task.
                if "wordpress" in hypothesis.lower():
                    # Ensure target_final_url is used for the task for consistency
                    final_url_for_task = gathered_data.get("target_final_url", target_url)
                    task = placeholder_wordpress_scan.delay(final_url_for_task)
                    celery_task_info = f"Dispatched placeholder_wordpress_scan task (ID: {task.id}) for {final_url_for_task} based on hypothesis."
                    logger.info(celery_task_info)
                else:
                    celery_task_info = "Hypothesis did not indicate WordPress; no specific WordPress task dispatched."
                    logger.info(f"{celery_task_info} For URL: {current_url_for_whois}")
            else:
                # Handle cases where LLM response format is unexpected
                hypothesis = "LLM response format was unexpected."
                logger.warning(f"LLM response format unexpected for {current_url_for_whois}. Response: {json.dumps(llm_data)}")
                celery_task_info = "Could not dispatch Celery task due to unexpected LLM response format."

        except httpx.HTTPStatusError as e:
            # Handle HTTP errors from the LLM Gateway
            error_message_prefix = f"Error from LLM Gateway for {current_url_for_whois}: {e.response.status_code}"
            try:
                error_body = e.response.json() # Attempt to parse JSON error from LLM gateway
                error_detail = f"{error_message_prefix} - {json.dumps(error_body)}"
            except: # Fallback if error body isn't JSON
                error_detail = f"{error_message_prefix} - {e.response.text[:100]}" # Truncate if not JSON or very long
            logger.error(error_detail)
            hypothesis = f"Failed to get hypothesis from LLM Gateway: HTTP {e.response.status_code}" # Keep hypothesis user-friendly
            celery_task_info = "Could not dispatch Celery task due to LLM Gateway error."
        except httpx.RequestError as e:
            # Handle network or connection errors when calling LLM Gateway
            logger.error(f"Could not connect to LLM Gateway for {current_url_for_whois}: {str(e)}")
            hypothesis = f"Could not connect to LLM Gateway: {str(e)}"
            celery_task_info = "Could not dispatch Celery task due to connection error with LLM Gateway."
        except Exception as e:
            # Catch any other unexpected errors during hypothesis generation or task dispatch
            logger.error(f"Unexpected error during hypothesis/task dispatch for {current_url_for_whois}: {str(e)}", exc_info=True) # Log stack trace
            hypothesis = f"Unexpected error generating hypothesis: {str(e)}"
            celery_task_info = f"Could not dispatch Celery task due to unexpected error: {str(e)}"

    # --- Step 5: Consolidate and Return Results ---
    # Add the generated hypothesis and Celery task info to the results.
    gathered_data["hypothesis_llm"] = hypothesis
    gathered_data["celery_task_dispatch_status"] = celery_task_info

    logger.info(f"Scan completed for {gathered_data.get('target_final_url', target_url)}. Returning results overview. Hypothesis: '{hypothesis}'. Celery task: '{celery_task_info}'.")
    return gathered_data
                "likely nature or primary technology of this website (e.g., 'This appears to be a blog', "
                "'This is likely an e-commerce site on Shopify', 'This might be a corporate page using WordPress'). "
                f"Data:\n{info_summary_str}"
            )
            logger.info(f"Sending prompt to LLM Gateway for hypothesis. Prompt (first 100 chars): {llm_prompt[:100]}...")
            llm_payload = {
                "prompt": llm_prompt,
                "model": "meta-llama/llama-3-8b-instruct:free",
                "max_tokens": 100,
                "temperature": 0.5
            }
            llm_response = await client.post(LLM_GATEWAY_URL, json=llm_payload, timeout=60.0)
            llm_response.raise_for_status()
            llm_data = llm_response.json()

            if llm_data.get("choices") and llm_data["choices"][0].get("message"):
                hypothesis = llm_data["choices"][0]["message"].get("content", "Could not extract hypothesis from LLM response.").strip()
                logger.info(f"LLM generated hypothesis: {hypothesis}")

                # 4. Dispatch Celery task based on hypothesis
                if "wordpress" in hypothesis.lower():
                    task = placeholder_wordpress_scan.delay(gathered_data.get("target_final_url", target_url))
                    celery_task_info = f"Dispatched placeholder_wordpress_scan task. ID: {task.id}"
                    logger.info(celery_task_info)
                else:
                    celery_task_info = "Hypothesis did not indicate WordPress, no specific WordPress task dispatched."
                    logger.info(celery_task_info)
            else:
                hypothesis = "LLM response format was unexpected."
                logger.warning(f"LLM response format unexpected: {llm_data}")
                celery_task_info = "Could not dispatch Celery task due to unexpected LLM response format."

        except httpx.HTTPStatusError as e:
            error_detail = f"Error from LLM Gateway: {e.response.status_code}"
            try: error_detail += f" - {e.response.json()}"
            except: error_detail += f" - {e.response.text[:100]}"
            logger.error(error_detail)
            hypothesis = f"Failed to get hypothesis from LLM Gateway: {error_detail}"
            celery_task_info = "Could not dispatch Celery task due to LLM Gateway error."
        except httpx.RequestError as e:
            logger.error(f"Could not connect to LLM Gateway: {str(e)}")
            hypothesis = f"Could not connect to LLM Gateway: {str(e)}"
            celery_task_info = "Could not dispatch Celery task due to connection error with LLM Gateway."
        except Exception as e:
            logger.error(f"Unexpected error during hypothesis generation or task dispatch: {str(e)}")
            hypothesis = f"Unexpected error generating hypothesis: {str(e)}"
            celery_task_info = f"Could not dispatch Celery task due to unexpected error: {str(e)}"

    gathered_data["hypothesis_llm"] = hypothesis
    gathered_data["celery_task_dispatch_status"] = celery_task_info
    return gathered_data
