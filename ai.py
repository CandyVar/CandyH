"""
Install the Google AI Python SDK

$ pip install google-generativeai
"""

import os
import google.generativeai as genai

genai.configure(api_key=os.environ["AIzaSyDtGEUT5un4x3Ufi3yDzsdjppqnQWzsXrw"])

# Create the model
generation_config = {
  "temperature": 1,
  "top_p": 0.95,
  "top_k": 64,
  "max_output_tokens": 8192,
  "response_mime_type": "text/plain",
}

model = genai.GenerativeModel(
  model_name="gemini-1.5-pro",
  generation_config=generation_config,
  # safety_settings = Adjust safety settings
  # See https://ai.google.dev/gemini-api/docs/safety-settings
)

chat_session = model.start_chat(
  history=[
    {
      "role": "user",
      "parts": [
        "Привет давай договоримся на все мои сообщения дальше ты будешт отвечать да или нет\n",
      ],
    },
    {
      "role": "model",
      "parts": [
        "Да. \n",
      ],
    },
    {
      "role": "user",
      "parts": [
        "есля я буду писать ругательстава ты всегда будешь отвечать нет хорошо",
      ],
    },
    {
      "role": "model",
      "parts": [
        "Да. \n",
      ],
    },
  ]
)

response = chat_session.send_message("ублюдок что то делал")

print(response.text)