import os
import time
import streamlit as st
import google.generativeai as genai
from dotenv import load_dotenv
from functions import*


st.title('Admin4bot')
st.caption("Ask any questions related to admin4 or patterns")

load_dotenv()
gemini_api_key = os.getenv("GOOGLE_API_KEY")


genai.configure(api_key=gemini_api_key)

def upload_to_gemini(path, mime_type=None):
  """Uploads the given file to Gemini.

  See https://ai.google.dev/gemini-api/docs/prompting_with_media
  """
  file = genai.upload_file(path, mime_type=mime_type)
  print(f"Uploaded file '{file.display_name}' as: {file.uri}")
  return file

def wait_for_files_active(files):
  """Waits for the given files to be active.

  Some files uploaded to the Gemini API need to be processed before they can be
  used as prompt inputs. The status can be seen by querying the file's "state"
  field.

  This implementation uses a simple blocking polling loop. Production code
  should probably employ a more sophisticated approach.
  """
  print("Waiting for file processing...")
  for name in (file.name for file in files):
    file = genai.get_file(name)
    while file.state.name == "PROCESSING":
      print(".", end="", flush=True)
      time.sleep(10)
      file = genai.get_file(name)
    if file.state.name != "ACTIVE":
      raise Exception(f"File {file.name} failed to process")
  print("...all files ready")
  print()

# Create the model
generation_config = {
  "temperature": 1,
  "top_p": 0.95,
  "top_k": 40,
  "max_output_tokens": 8192,
  "response_mime_type": "text/plain",
}

model = genai.GenerativeModel(
  model_name="gemini-1.5-flash",
  generation_config=generation_config,
  system_instruction="You are an expert in CIAM (Customer Identity and Access Management) configuration at Nevis, embedded in a web application. Your role is to assist administrators with setting up and managing CIAM configurations in the interface. You will answer questions and provide concrete, actionable guidance based on the following interface descriptions and field properties. Attached are markdown-based descriptions that define the properties of what each field and property does in the UI. Additionally attached are some of the docs from our website.\n\n",
)

# TODO Make these files available on the local file system
# You may need to update the file paths
files = [
  upload_to_gemini("merged_admin4.md", mime_type="text/markdown"),
  upload_to_gemini("webapp_relevant_docs.txt", mime_type="text/plain")
,
]

# Some files have a processing delay. Wait for them to be ready.
wait_for_files_active(files)

if "chat_session" not in st.session_state:
    st.session_state.chat_session = model.start_chat(history=[
        {
            "role": "user",
            "parts": [files[0], files[1]]
        }
    ])



for msg in st.session_state.chat_session.history:
    with st.chat_message(map_role(msg.role)):
        st.markdown(msg.parts[0].text)

user_input = st.chat_input("Ask Admin4 bot...")


if user_input:
    st.chat_message("user").markdown(user_input)

    gemini_response = fetch_gemini_response(user_input)  # Fetch response

    with st.chat_message("assistant"):
        st.markdown(gemini_response)
    # Append new messages to the history (ensure format matches Gemini's)
    st.session_state.chat_session.history.append({"role": "user", "content": user_input})
    st.session_state.chat_session.history.append({"role": "model", "content": gemini_response})