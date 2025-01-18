import os
from dotenv import load_dotenv
from openai import OpenAI
import subprocess
import sys

load_dotenv()

# OPEN_AI_KEY = os.getenv("OPEN_AI_KEY")

def execute_command(command):
    try:
        result = subprocess.check_output(command, shell=True, text=True).strip()
        return result
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"


def create_prompt():
    # Define the commands to execute
    commands = {
        "Current Shell": "echo $SHELL",
        "Shell Version": "zsh --version || bash --version",
        "System Architecture": "uname -m",
        "Detailed System Info": "uname -a",
    }

    # Execute the commands and gather results
    with open('system_prompt.txt', "w") as f:
        f.write("You are a terminal assistant. Respond to user questions about terminal commands succinctly and clearly and in plain text with no markdown. "
                "Be sure to explain what any args or flags do. Here is some information about the user's system:\n")
        for key, cmd in commands.items():
            result = execute_command(cmd)
            f.write(f"{key}: {result}\n")


def main(user_prompt):
    # check if system_prompt.txt file exists. If it doesn't, call create_prompt().
    if not os.path.exists("system_prompt.txt"):
        create_prompt()

    # load the system prompt from the file
    with open("system_prompt.txt", "r") as file:
        system_prompt = file.read()

    client = OpenAI()

    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": user_prompt
                    }
                ]
            }
        ]
    )
    response = completion.choices[0].message.content
    print(response)


if __name__ == '__main__':
    arg = " ".join(sys.argv[1:]).strip()
    if not arg:
        arg = "list files with size in KB, MB, etc."
    main(arg)
