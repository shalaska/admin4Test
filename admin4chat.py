import os
import time
import datetime
import uuid
import traceback
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
from google.generativeai import caching

# Set page config to wide mode
st.set_page_config(layout="wide")

# --- Nevis Copilot ---
st.image('nevis.svg', width=100)
st.title('Nevis Copilot')
st.caption("Experience the future of Nevis configuration with our AI assistant.")
# Add HTML with CSS to create a sticky footer
st.markdown(
    """
    <style>
        .sticky-footer {
            position: fixed;
            left: 0;
            bottom: 0;
            width: 100%;
            background-color: #f0f0f5; 
            padding: 10px;
            text-align: center;
            z-index: 100; 
        }
    </style>
    <div class="sticky-footer">
        The Nevis Copilot is an experimental AI assistant. The answers may contain errors and should be carefully reviewed.
    </div>
    """,
    unsafe_allow_html=True
)

# --- Gemini setup ---
load_dotenv()
gemini_api_key = os.getenv("GOOGLE_API_KEY")
genai.configure(api_key=gemini_api_key)


def upload_to_gemini(path, mime_type=None):
    """Uploads the given file to Gemini, but only if it hasn't been uploaded already."""
    try:
        # Get a list of existing files in Gemini
        existing_files = list(genai.list_files())
        existing_file_names = [file.display_name for file in existing_files]

        # Check if the file has already been uploaded
        if os.path.basename(path) in existing_file_names:
            print(f"File '{path}' already exists in Gemini. Skipping upload.")
            # Find the existing file object
            file = next((file for file in existing_files if file.display_name == os.path.basename(path)), None)
            if file is None:
                raise ValueError(f"Could not find existing file object for '{path}'")
        else:
            # If the file doesn't exist, upload it
            file = genai.upload_file(path, mime_type=mime_type)
            print(f"Uploaded file '{file.display_name}' as: {file.uri}")

        return file
    except Exception as e:
        print(f"Error in upload_to_gemini: {e}")
        traceback.print_exc()
        raise


def wait_for_files_active(files):
    """Waits for the given files to be active."""
    try:
        print("Waiting for file processing...")
        for file in files:
            while file.state.name == "PROCESSING":
                print(".", end="", flush=True)
                time.sleep(10)
                file = genai.get_file(file.name)  # Refresh file status
            if file.state.name != "ACTIVE":
                raise Exception(f"File {file.name} failed to process: {file.state.name}")
        print("...all files ready")
    except Exception as e:
        print(f"Error in wait_for_files_active: {e}")
        traceback.print_exc()
        raise


def load_and_upload_files():
    try:
        files = [
            upload_to_gemini("patternspdf-compressed-compressed-pages-1.pdf", mime_type="application/pdf"),
            upload_to_gemini("patternspdf-compressed-compressed-pages-2.pdf", mime_type="application/pdf"),
            upload_to_gemini("patternspdf-compressed-compressed-pages-3.pdf", mime_type="application/pdf"),
            upload_to_gemini("patternspdf-compressed-compressed-pages-4.pdf", mime_type="application/pdf"),
            upload_to_gemini("patternspdf-compressed-compressed-pages-5.pdf", mime_type="application/pdf"),
            upload_to_gemini("webapp_relevant_docs.txt", mime_type="text/plain")
        ]
        print(files)  # Print the list to inspect its contents
        for file in files:
            print(type(file))  # Print the type of each element
        wait_for_files_active(files)
        return files
    except Exception as e:
        print(f"Error in load_and_upload_files: {e}")
        traceback.print_exc()
        raise


def create_context_cache(files, model_name, display_name, ttl_minutes):
    """Creates a context cache with the specified files."""
    try:
        cache = caching.CachedContent.create(
            model=model_name,
            display_name=display_name,
            contents=files,
            ttl=datetime.timedelta(minutes=ttl_minutes),
        )
        print(f"Created cache '{cache.display_name}' with ID: {cache.name}")
        return cache
    except Exception as e:
        print(f"Error creating cache: {e}")
        traceback.print_exc()
        # Check if the error is related to the quota
        if "TotalCachedContentStorageTokensPerModelFreeTier limit exceeded" in str(e):
            return None
        elif "'str' object has no attribute 'name'" in str(e):  # Check for the specific error
            print("Error: One of the files is not a valid File object.")
            return None
        else:
            raise  # Re-raise other exceptions


def delete_oldest_caches(existing_caches, current_cache_name):
    """Deletes the oldest caches, excluding the current cache."""
    try:
        # Exclude the current cache from deletion
        caches_to_delete = [cache for cache in existing_caches
                            if cache.display_name != current_cache_name]

        # Sort remaining caches by creation time (oldest first)
        sorted_caches = sorted(caches_to_delete, key=lambda x: x.create_time)

        # Delete only if there are caches to delete
        if sorted_caches:
            cache_to_delete = sorted_caches[0]  # Delete the oldest one
            print(f"Deleting old cache: {cache_to_delete.display_name} (ID: {cache_to_delete.name})")
            caching.CachedContent.delete(cache_to_delete)

    except Exception as e:
        print(f"Failed to delete old caches: {e}")
        traceback.print_exc()


def delete_all_caches():
    """Deletes all context caches."""
    try:
        existing_caches = list(caching.CachedContent.list())
        for cache in existing_caches:
            print(f"Deleting cache: {cache.display_name} (ID: {cache.name})")
            caching.CachedContent.delete(cache)
    except Exception as e:
        print(f"Failed to delete all caches: {e}")
        traceback.print_exc()


@st.cache_resource
def initialize_context_cache():
    cache_name = f"Nevis Docs Cache - {uuid.uuid4()}"
    try:
        # 1. Check for existing caches
        existing_caches = list(caching.CachedContent.list())
        found_cache = None
        for cache in existing_caches:
            if cache.display_name.startswith("Nevis Docs Cache"):
                found_cache = cache
                print(f"Found existing cache: {cache.display_name} (ID: {cache.name})")
                break

        if found_cache:
            # Check if the cache is expired
            now = datetime.datetime.now(datetime.timezone.utc)  # Make 'now' timezone-aware (UTC)
            cache_age = now - found_cache.create_time
            if cache_age > datetime.timedelta(minutes=1440):  # 24 hours
                print(f"Cache '{found_cache.display_name}' is expired. Deleting...")
                caching.CachedContent.delete(found_cache)
            else:
                return found_cache

        # 2. If no suitable cache is found, create a new one
        files = load_and_upload_files()

        # Attempt to create the cache with retries
        max_retries = 3
        retries = 0
        while retries < max_retries:
            new_cache = create_context_cache(
                files=files,
                model_name="gemini-1.5-flash-002",
                display_name=cache_name,
                ttl_minutes=1440
            )
            if new_cache:
                break
            else:
                retries += 1
                print(f"Cache creation failed (attempt {retries}/{max_retries}). Clearing existing caches and retrying...")

                # Clear all existing caches ONLY on retry
                existing_caches = list(caching.CachedContent.list())
                for cache in existing_caches:
                    print(f"Deleting cache: {cache.display_name} (ID: {cache.name})")
                    caching.CachedContent.delete(cache)

                time.sleep(5)

        if new_cache is None:
            raise Exception("Failed to create cache after multiple retries.")

        return new_cache

    except Exception as e:
        print(f"Error in initialize_context_cache: {e}")
        traceback.print_exc()
        raise Exception(f"Failed to initialize context cache: {e}")


# Initialize the context cache
cache = initialize_context_cache()

# System configuration
system_instruction="You are an expert in CIAM (Customer Identity and Access Management) configuration at Nevis, embedded in a web application. Your role is to assist administrators with setting up and managing CIAM configurations in the interface. You will answer questions and provide concrete, actionable guidance based on the following interface descriptions and field properties. You should try to always list assumed prerequisites required to answer the question. Attached are markdown-based descriptions that define the properties of what each field and property does in the UI. Additionally attached are some of the docs from our website.\n\n"
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",
}

# Use cached context in the model
model = genai.GenerativeModel(
  model_name="gemini-1.5-flash-002",
  generation_config=generation_config,
  system_instruction=system_instruction
)


def fetch_gemini_response(user_input, chat_session):
    """Fetches a response from the Gemini model."""
    try:
        response = chat_session.send_message(user_input)
        return {"response": response.text, "error": None}
    except Exception as e:
        error_message = f"An error occurred while fetching the response: {e}"
        print(error_message)
        traceback.print_exc()
        return {"response": None, "error": error_message}


# Initialize chat session
if "chat_session" not in st.session_state:
    st.session_state.chat_session = model.start_chat(history=[
        {"role": "user", "parts": [{"text": "Added Nevis docs"}]},
        {"role": "assistant", "parts": [{"text": "Nevis docs processed and ready for questions."}]}
    ])

# Initialize chat history in session state if not present
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

# Render chat history from session state
for message in st.session_state.chat_history:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Input for new user queries
user_input = st.chat_input("Ask Nevis Copilot anything...")

if user_input:
    # Display the user message immediately
    st.chat_message("user").markdown(user_input)
    st.session_state.chat_history.append({"role": "user", "content": user_input})

    # Check for the "delete cache" command
    if user_input.strip().lower() == "delete cache":
        with st.spinner("Deleting cache and re-initializing..."):
            try:
                delete_all_caches() 
                initialize_context_cache()  # Re-initialize the cache
                st.session_state.chat_session = model.start_chat(history=[
                    {"role": "user", "parts": [{"text": "Added Nevis docs"}]},
                    {"role": "assistant", "parts": [{"text": "Nevis docs processed and ready for questions."}]}
                ])  # Reset the chat session
                st.success("Cache deleted and re-initialized successfully!")
            except Exception as e:
                st.error(f"An error occurred while deleting and re-initializing the cache: {e}")
    else:
        with st.spinner("Thinking..."):
            try:
                # Fetch Gemini response
                gemini_response = fetch_gemini_response(user_input, st.session_state.chat_session)

                # Check for errors in the response
                if gemini_response.get("error"):
                    st.error(gemini_response["error"])  # Display the error message
                else:
                    # Update chat history and display the response
                    st.session_state.chat_history.append({"role": "assistant", "content": gemini_response["response"]})
                    st.chat_message("assistant").markdown(gemini_response["response"])

            except Exception as e:
                st.error(f"An error occurred: {e}")