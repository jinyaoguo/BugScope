# Imports
from openai import *
from pathlib import Path
from typing import Tuple
import google.generativeai as genai
import signal
import sys
import tiktoken
import time
import os
import concurrent.futures
from functools import partial
import threading

import json
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
import boto3
from ui.logger import Logger


class LLM:
    """
    An online inference model using different LLMs:
    - Gemini
    - OpenAI: GPT-3.5, GPT-4, o4-mini
    - DeepSeek: R1
    - Claude: 3.5 and 3.7
    """

    def __init__(
        self, 
        online_model_name: str,
        logger: Logger,
        temperature: float = 0.0,
        system_role="You are a experienced programmer and good at understanding programs written in mainstream programming languages.",
        max_output_length=4096,
    ) -> None:
        self.online_model_name = online_model_name
        self.encoding = tiktoken.encoding_for_model("gpt-3.5-turbo-0125") # We only use gpt-3.5 to measure token cost
        self.temperature = temperature
        self.systemRole = system_role
        self.logger = logger
        self.max_output_length = max_output_length
        return


    def infer(
        self, message: str, is_measure_cost: bool = False
    ) -> Tuple[str, int, int]:
        self.logger.print_log(self.online_model_name, "is running")
        output = ""
        if "gemini" in self.online_model_name:
            output = self.infer_with_gemini(message)
        elif (
            "o3-mini" in self.online_model_name
            or "o4-mini" in self.online_model_name
            or "gpt-5" in self.online_model_name
        ):
            output = self.infer_with_openai_reasoning_model(message)
        elif "gpt" in self.online_model_name:
            output = self.infer_with_openai_model(message)
        elif "claude" in self.online_model_name:
            output = self.infer_with_claude(message)
        elif "deepseek-reasoner" in self.online_model_name:
            output = self.infer_with_amazon_deepseek_R1(message)
        elif "deepseek-chat" in self.online_model_name:
            output = self.infer_with_deepseek_model(message)
        else:
            raise ValueError("Unsupported model name")
            
        input_token_cost = (
            0
            if not is_measure_cost
            else len(self.encoding.encode(self.systemRole))
            + len(self.encoding.encode(message))
        )
        output_token_cost = (
            0 if not is_measure_cost else len(self.encoding.encode(output))
        )
        return output, input_token_cost, output_token_cost


    def run_with_timeout(self, func, timeout):
        """Run a function with timeout that works in multiple threads"""
        result = None
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func)
            try:
                result = future.result(timeout=timeout)
                return result
            except concurrent.futures.TimeoutError:
                self.logger.print_log("Operation timed out")
                if not future.done():
                    future.cancel()
                raise
            except Exception as e:
                self.logger.print_log(f"Operation failed: {e}")
                raise


    def infer_with_gemini(self, message: str) -> str:
        """Infer using the Gemini model from Google Generative AI"""
        gemini_model = genai.GenerativeModel("gemini-pro")
        
        def call_api():
            message_with_role = self.systemRole + "\n" + message
            safety_settings = [
                {
                    "category": "HARM_CATEGORY_DANGEROUS",
                    "threshold": "BLOCK_NONE",
                },
                # ...existing safety settings...
            ]
            response = gemini_model.generate_content(
                message_with_role,
                safety_settings=safety_settings,
                generation_config=genai.types.GenerationConfig(
                    temperature=self.temperature
                ),
            )
            return response.text

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=50)
                if output:
                    self.logger.print_log("Inference succeeded...")
                    return output
            except Exception as e:
                self.logger.print_log(f"API error: {e}")
            time.sleep(2)
        
        return ""


    def infer_with_openai_model(self, message):
        """Infer using the OpenAI model"""
        api_key = os.environ.get("OPENAI_API_KEY").split(":")[0]
        model_input = [
            {"role": "system", "content": self.systemRole},
            {"role": "user", "content": message},
        ]
        
        def call_api():
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=self.online_model_name,
                messages=model_input,
                temperature=self.temperature,
            )
            return response.choices[0].message.content

        tryCnt = 0
        timeout = 100
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=timeout)
                if output:
                    return output
            except concurrent.futures.TimeoutError:
                self.logger.print_log(f"Timeout occurred, increasing timeout for next attempt")
                timeout = min(timeout * 1.5, 300)
            except Exception as e:
                self.logger.print_log(f"API error: {str(e)}")
            time.sleep(2)
        
        return ""
    

    def infer_with_openai_reasoning_model(self, message):
        """Infer using the openai reasoning model"""
        api_key = os.environ.get("OPENAI_API_KEY").split(":")[0]
        model_input = [
            {"role": "system", "content": self.systemRole},
            {"role": "user", "content": message},
        ]
        
        def call_api():
            client = OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=self.online_model_name,
                messages=model_input
            )
            return response.choices[0].message.content

        tryCnt = 0
        timeout = 300
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=timeout)
                if output:
                    return output
            except concurrent.futures.TimeoutError:
                self.logger.print_log(f"Timeout occurred, increasing timeout for next attempt")
            except Exception as e:
                self.logger.print_log(f"API error: {str(e)}")
            time.sleep(2)
        
        return ""
    

    def infer_with_deepseek_model(self, message):
        """
        Infer using the DeepSeek model from official API.
        """
        api_key = os.environ.get("DEEPSEEK_API_KEY2")
        model_input = [
            {
                "role": "system",
                "content": self.systemRole,
            },
            {"role": "user", "content": message},
        ]

        def call_api():
            client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/")
            response = client.chat.completions.create(
                model=self.online_model_name,
                messages=model_input,
                temperature=self.temperature,
                max_tokens=self.max_output_length,
            )
            return response.choices[0].message.content

        tryCnt = 0
        timeout = 600
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=timeout)
                if output:
                    return output
            except concurrent.futures.TimeoutError:
                self.logger.print_log(f"Timeout occurred, increasing timeout for next attempt")
                timeout *= 2
            except Exception as e:
                self.logger.print_log(f"API error: {str(e)}")
            time.sleep(2)
        
        return ""


    def infer_with_amazon_deepseek_R1(self, message):
        """
        Infer using the DeepSeek R1 model via AWS Bedrock.
        Uses invoke_model API with proper formatting for DeepSeek-R1.
        """
        model_id = "us.deepseek.r1-v1:0"
        
        formatted_prompt = f"""
        <｜begin▁of▁sentence｜><｜User｜>{self.systemRole}
        {message}<｜Assistant｜><think>\n
        """

        body = json.dumps({
            "prompt": formatted_prompt,
            "max_tokens": self.max_output_length,
            "temperature": self.temperature,
            "top_p": 0.9,
        })
        
        def call_api():
            client = boto3.client(
                "bedrock-runtime", 
                region_name="us-west-2",
                config=Config(read_timeout=timeout)
            )
            
            response = client.invoke_model(
                modelId=model_id,
                contentType="application/json",
                body=body
            )
            
            response = json.loads(response["body"].read())
            
            if "choices" in response and len(response["choices"]) > 0:
                return response["choices"][0]["text"]
            else:
                self.logger.print_log("No choices in model response")
                return ""

        tryCnt = 0
        timeout = 600
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=timeout)
                if output:
                    return output
            except concurrent.futures.TimeoutError:
                self.logger.print_log(f"Timeout occurred, increasing timeout for next attempt")
                timeout = min(timeout * 1.5, 600)
            except Exception as e:
                self.logger.print_log(f"API error: {str(e)}")
            time.sleep(2)
        
        return ""
        

    def infer_with_claude(self, message):
        """Infer using the Claude model via AWS Bedrock"""
        timeout = 300
        model_input = [
            {
                "role": "assistant",
                "content": self.systemRole,
            },
            {"role": "user", "content": message},
        ]
        
        if "3.5" in self.online_model_name:
            model_id = "anthropic.claude-3-5-sonnet-20241022-v2:0"
            body = json.dumps({
                "messages": model_input,
                "max_tokens": self.max_output_length,
                "anthropic_version": "bedrock-2023-05-31",
                "temperature": self.temperature,
                "top_k": 50,
            })
        if "3.7" in self.online_model_name:
            model_id = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
            body = json.dumps({
                "messages": model_input,
                "max_tokens": self.max_output_length,
                "thinking":{
                    "type": "enabled",
                    "budget_tokens": 2048
                },
                "anthropic_version": "bedrock-2023-05-31",
            })
        
        if "4" in self.online_model_name:
            model_id = "us.anthropic.claude-sonnet-4-20250514-v1:0"
            body = json.dumps({
                "messages": model_input,
                "max_tokens": self.max_output_length,
                "thinking":{
                    "type": "enabled",
                    "budget_tokens": 2048
                },
                "anthropic_version": "bedrock-2023-05-31",
            })
        
        if "4.5" in self.online_model_name:
            model_id = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
            body = json.dumps({
                "messages": model_input,
                "max_tokens": self.max_output_length,
                "thinking":{
                    "type": "enabled",
                    "budget_tokens": 2048
                },
                "anthropic_version": "bedrock-2023-05-31",
            })

        def call_api():
            client = boto3.client(
                "bedrock-runtime", 
                region_name="us-west-2",
                config=Config(read_timeout=timeout)
            )
            
            response = client.invoke_model(
                modelId=model_id,
                contentType="application/json",
                body=body
            )["body"].read().decode("utf-8")
            
            response = json.loads(response)

            if "3.5" in self.online_model_name:
                result = response["content"][0]["text"]
            else:
                result = response["content"][1]["text"]
            return result

        tryCnt = 0
        while tryCnt < 5:
            tryCnt += 1
            try:
                output = self.run_with_timeout(call_api, timeout=timeout)
                if output:
                    return output
            except concurrent.futures.TimeoutError:
                self.logger.print_log(f"Timeout occurred, increasing timeout for next attempt")
                timeout = min(timeout * 1.5, 600)
            except Exception as e:
                self.logger.print_log(f"API error: {str(e)}")
            time.sleep(2)
        
        return ""


# test

if __name__ == "__main__":
    # Set up the logger
    logger = Logger("test.log")
    
    # Initialize the LLM class with the desired model
    llm = LLM(
        online_model_name="gpt-5-mini",
        logger=logger,
        temperature=0,
        system_role="You are a good C/C++ programmer.",
        max_output_length=4096,
    )

    # Test the inference method
    message = "What is the capital of France?"
    output, input_cost, output_cost = llm.infer(message, is_measure_cost=True)
    print(f"Output: {output}")
    print(f"Input Token Cost: {input_cost}")
    print(f"Output Token Cost: {output_cost}")