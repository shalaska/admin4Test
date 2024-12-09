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
st.title('Admin4 Assistant')
st.caption("Ask any questions related to admin4 or patterns")

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

@st.cache_resource
def initialize_context_cache():
    files = load_and_upload_files()
    return create_context_cache(
        files=files,
        model_name="gemini-1.5-flash-002",
        display_name="Nevis Docs Cache",
        ttl_minutes=60
    )



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
        return response.text
    except genai.errors.GenerativeAIError as e:
        raise
    except Exception as e:
        raise

if "chat_session" not in st.session_state:
    st.session_state.chat_session = model.start_chat(history=[
        {"role": "user", "parts": [{"text": "Added Nevis docs"}]},
        {"role": "assistant", "parts": [{"text": "Nevis docs processed and ready for questions."}]}
    ])

for msg in st.session_state.chat_session.history:
    with st.chat_message("user" if msg.role == "user" else "assistant"):
        if hasattr(msg.parts[0], 'text'):
            st.markdown(msg.parts[0].text)

user_input = st.chat_input("Ask Admin4 assistant anything...")

if user_input:
    st.chat_message("user").markdown(user_input)
    with st.spinner("Thinking..."):
        try:
            gemini_response = fetch_gemini_response(user_input, st.session_state.chat_session)
            with st.chat_message("assistant"):
                st.markdown(gemini_response)
            st.session_state.chat_session.history.append({"role": "user", "content": user_input})
            st.session_state.chat_session.history.append({"role": "assistant", "content": gemini_response})
        except Exception as e:
            st.error(f"An error occurred: {e}")
