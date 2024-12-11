import os
import time
import datetime
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
from google.generativeai import caching

# Set page config to wide mode
st.set_page_config(layout="wide")

# --- Admin4bot ---
st.image('nevis.svg', width=100) 
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

def delete_oldest_caches(existing_caches):
    """Deletes the oldest caches to free up space."""
    try:
        # Sort caches by creation time (oldest first)
        sorted_caches = sorted(existing_caches, key=lambda x: x.create_time)
        for cache in sorted_caches:
            print(f"Deleting old cache: {cache.display_name} (ID: {cache.name})")
            caching.CachedContent.delete(cache.name)
            # Break after deleting one cache to avoid over-deleting
            break
    except Exception as e:
        print(f"Failed to delete old caches: {e}")

@st.cache_resource
def initialize_context_cache():
    cache_name = "Nevis Docs Cache"
    try:
        # Check if the cache already exists
        existing_caches = list(caching.CachedContent.list())  # Convert to list here
        for existing_cache in existing_caches:
            if existing_cache.display_name == cache_name:
                print(f"Using existing cache: {existing_cache.display_name}")
                return existing_cache

        # If the cache limit is exceeded, clean up older caches
        max_cache_limit = 10  # Adjust based on your quota
        if len(existing_caches) >= max_cache_limit:
            print(f"Cache limit exceeded ({len(existing_caches)}/{max_cache_limit}). Cleaning up old caches...")
            delete_oldest_caches(existing_caches)

        # Create a new cache if none exists
        files = load_and_upload_files()
        new_cache = create_context_cache(
            files=files,
            model_name="gemini-1.5-flash-002",
            display_name=cache_name,
            ttl_minutes=60
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
    print(f"Gemini response: {response.text}")  # Log the response to the console
    return response.text
  except Exception as e:
    print(f"An error occurred while fetching the response: {e}")  # Log the error to the console
    return "I'm sorry, I encountered an error while processing your request."
  
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

            # Update chat history in session state
            st.session_state.chat_history.append({"role": "assistant", "content": gemini_response})

            # Display the assistant response
            st.chat_message("assistant").markdown(gemini_response)

        except Exception as e:
            st.error(f"An error occurred: {e}")