import os
import time
import datetime
import uuid
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
from google.generativeai import caching

# Set page config to wide mode
st.set_page_config(layout="wide")

# --- Admin4bot ---
st.image('nevis.svg', width=100)  # Replace 'nevis.svg' with the actual path to your image
st.title('Nevis Copilot')
st.caption("Experience the future of Nevis configuration with our AI assistant")

# --- Gemini setup ---
load_dotenv()
gemini_api_key = os.getenv("GOOGLE_API_KEY")
genai.configure(api_key=gemini_api_key)

def upload_to_gemini(path, mime_type=None):
    """Uploads the given file to Gemini."""
    file = genai.upload_file(path, mime_type=mime_type)
    print(f"Uploaded file '{file.display_name}' as: {file.uri}")
    return file

def wait_for_files_active(files):
    """Waits for the given files to be active."""
    print("Waiting for file processing...")
    for file in files:
        while file.state.name == "PROCESSING":
            print(".", end="", flush=True)
            time.sleep(10)
            file = genai.get_file(file.name)
        if file.state.name != "ACTIVE":
            raise Exception(f"File {file.name} failed to process")
    print("...all files ready")

@st.cache_resource
def load_and_upload_files():
    files = [
        upload_to_gemini("patternspdf-compressed-compressed-pages-1.pdf", mime_type="application/pdf"),
        upload_to_gemini("patternspdf-compressed-compressed-pages-2.pdf", mime_type="application/pdf"),
        upload_to_gemini("patternspdf-compressed-compressed-pages-3.pdf", mime_type="application/pdf"),
        upload_to_gemini("patternspdf-compressed-compressed-pages-4.pdf", mime_type="application/pdf"),
        upload_to_gemini("patternspdf-compressed-compressed-pages-5.pdf", mime_type="application/pdf"),
        upload_to_gemini("webapp_relevant_docs.txt", mime_type="text/plain")
    ]
    wait_for_files_active(files)
    return files

def create_context_cache(files, model_name, display_name, ttl_minutes):
    """Creates a context cache with the specified files."""
    cache = caching.CachedContent.create(
        model=model_name,
        display_name=display_name,
        contents=files,
        ttl=datetime.timedelta(minutes=ttl_minutes),
    )
    print(f"Created cache '{cache.display_name}' with ID: {cache.name}")
    return cache

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
            caching.CachedContent.delete(cache_to_delete.name)

    except Exception as e:
        print(f"Failed to delete old caches: {e}")

@st.cache_resource
def initialize_context_cache():
    # Generate a unique cache name using a UUID
    cache_name = f"Nevis Docs Cache - {uuid.uuid4()}"
    try:
        existing_caches = list(caching.CachedContent.list())

        # If the cache limit is exceeded, clean up older caches
        max_cache_limit = 10
        if len(existing_caches) >= max_cache_limit:
            print(f"Cache limit exceeded ({len(existing_caches)}/{max_cache_limit}). Cleaning up old caches...")
            delete_oldest_caches(existing_caches, cache_name)

        # Create a new cache
        files = load_and_upload_files()
        new_cache = create_context_cache(
            files=files,
            model_name="gemini-1.5-flash-002",
            display_name=cache_name,
            ttl_minutes=1440  # Increased TTL to 24 hours
        )
        return new_cache

    except Exception as e:
        raise Exception(f"Failed to initialize context cache: {e}")

# Initialize the context cache
cache = initialize_context_cache()

# Use cached context in the model
model = genai.GenerativeModel.from_cached_content(cached_content=cache)

# System configuration
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",
}

def fetch_gemini_response(user_input, chat_session):
    """Fetches a response from the Gemini model."""
    try:
        response = chat_session.send_message(user_input)
        return {"response": response.text, "error": None}
    except Exception as e:
        error_message = f"An error occurred while fetching the response: {e}"
        print(error_message)
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
user_input = st.chat_input("Ask Admin4 assistant anything...")

if user_input:
    # Display the user message immediately
    st.chat_message("user").markdown(user_input)
    st.session_state.chat_history.append({"role": "user", "content": user_input})

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