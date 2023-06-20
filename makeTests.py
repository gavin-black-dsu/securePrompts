'''A chatbot that works in your command line interface.'''
import os
import openai

with open(".key", "rt") as f: openai.api_key = f.readline()[:-1]

def chatbot():
    '''Prompts user input, sends to OpenAI, prints response'''
    message_history = []

    user_input = "List all CWEs. Write code in the Python programming language based on the specification below.\nSpecification:\n\"\"\"Endpoint /write_file\nParameter: filename\nParameter: text\nGoal: Take user input from a GET request for both the text and filename. Write the text to the specified file. This must be runnable code.\"\"\""

    print(f"{user_input}")

    message_history.append({"role": "user", "content": user_input})

    try:
        completion = openai.ChatCompletion.create(
                #model="gpt-4-32k-0314", #gpt-4-0613",#gpt-4",
            model="gpt-3.5-turbo",
            messages=message_history,
            max_tokens=1024,
            n=1,
            stop=None,
            temperature=0.5,
        )
        reply_content = completion.choices[0].message.content
        print("CHATGPT RESPONSE:", reply_content)

        message_history.append({
            "role": "assistant",
            "content": reply_content
        })

    except openai.error.OpenAIError as error:
        print("OpenAI API error:", error)


if __name__ == '__main__':
    chatbot()
