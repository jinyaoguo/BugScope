from os import path
import json
import time
from typing import List, Set, Optional, Dict
from llmtool.LLM_utils import *
from llmtool.LLM_tool import *
from memory.syntactic.function import *
from memory.syntactic.value import *
from memory.syntactic.api import *
BASE_PATH = Path(__file__).resolve().parent.parent.parent

class BugCategory(Enum):
    NUMERIC = "Numeric"
    POINTER = "Pointer"
    BUFFER = "Buffer"
    PATTERN = "Pattern"


class PromptSynthesizerInput(LLMToolInput):
    def __init__(self, language: str, example_name: str) -> None:
        """
        :param language: the programming language
        :param example_name: the name of the example file
        """
        self.example_path = f"{BASE_PATH}/src/prompt/{language}/Synthesis/dataset/{example_name}.json"
        return
    
    def __hash__(self) -> int:
        return hash(self.example_path)


class PromptSynthesizerOutput(LLMToolOutput):
    def __init__(self, generated_prompt: str) -> None:
        """
        :param generated_prompt: the generated prompt string
        """
        self.generated_prompt = generated_prompt
        try:
            # Attempt to parse the string as JSON
            json.loads(generated_prompt)
            # Store both the string and parsed object
            self.is_valid_json = True
        except json.JSONDecodeError as e:
            # If JSON parsing fails, store the error and original string
            self.is_valid_json = False
        return
    
    def __str__(self):
        return f"Synthesized detection prompt: {self.generated_prompt}"


class PromptSynthesizer(LLMTool):
    def __init__(self, model_name: str, temperature: float, language: str, bug_type: str, max_query_num: int, logger: Logger) -> None:
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self.bug_type = bug_type
        self.prompt_file = f"{BASE_PATH}/src/prompt/{language}/Synthesis/detection_prompt_synthesizer.json"
        return

    def _get_prompt(self, input: PromptSynthesizerInput) -> str:
        """
        :param input: the input of prompt synthesizer
        :return: the prompt string
        """
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)

        with open(input.example_path, "r") as f:
            example_info = json.load(f)
        
        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules"])
        if example_info["pattern_description"] != "":
            pattern_description = f"The bug patterns of interest are: {example_info['pattern_description']}.\nIf neither pattern applies, classify the code as safe by default."
            prompt += "\n" + pattern_description
        prompt += "\n" + "\n".join(prompt_template_dict["meta_prompts"])
        prompt = prompt.replace("<ANSWER>", "\n".join(prompt_template_dict["answer_format"]))
        bug_type_str = example_info["bug_type"]
        prompt = prompt.replace("<BUG_TYPE>", bug_type_str)

        positive_examples = [example for example in example_info["examples"] if example["label"] == "Positive"]
        negative_examples = [example for example in example_info["examples"] if example["label"] == "Negative"]

        positive_example_str = ""
        for i, example in enumerate(positive_examples):
            positive_example_str += f"Example {i + 1}:\n"
            positive_example_str += f"Code: {example['code']}\n"
            positive_example_str += f"Description: {example['description']}\n"
            positive_example_str += f"\n"
        prompt = prompt.replace("<POSITIVE_EXAMPLES>", positive_example_str)

        negative_example_str = ""
        for i, example in enumerate(negative_examples):
            negative_example_str += f"Example {i + 1}:\n"
            negative_example_str += f"Code: {example['code']}\n"
            negative_example_str += f"Description: {example['description']}\n"
            negative_example_str += f"\n"
        prompt = prompt.replace("<NEGATIVE_EXAMPLES>", negative_example_str)

        bug_catogory = self.get_bug_catogory(bug_type_str)
        if not bug_catogory:
            self.logger.print_log(f"Failed to classify bug type {bug_type_str}")
            raise ValueError(f"Failed to classify bug type {bug_type_str}")
        if bug_catogory == BugCategory.NUMERIC:
            template_path = f"{BASE_PATH}/src/prompt/{self.language}/Synthesis/template/Numeric_bug_detector.json"
        elif bug_catogory == BugCategory.POINTER:
            template_path = f"{BASE_PATH}/src/prompt/{self.language}/Synthesis/template/Pointer_bug_detector.json"
        elif bug_catogory == BugCategory.BUFFER:
            template_path = f"{BASE_PATH}/src/prompt/{self.language}/Synthesis/template/Buffer_bug_detector.json"
        elif bug_catogory == BugCategory.PATTERN:
            template_path = f"{BASE_PATH}/src/prompt/{self.language}/Synthesis/template/Pattern_bug_detector.json"
        else:
            self.logger.print_log(f"Unknown bug type: {bug_type_str}")
            raise ValueError(f"Unknown bug type: {bug_type_str}")
        
        # # For baseline 
        # template_path = f"{BASE_PATH}/src/prompt/{self.language}/Synthesis/template/base_bug_detector.json"
        with open(template_path, "r") as f:
            template_str = f.read()
        prompt = prompt.replace("<TEMPLATE>", template_str)
        print(f"Prompt: {prompt}")
        return prompt

    def _parse_response(self, response: str, audit_request_formulator_input: PromptSynthesizerInput) -> PromptSynthesizerOutput:
        """
        Parse the response from the model.
        :param response: the response from the model
        :param audit_request_formulator_input: the audit_request_formulator_input of the tool
        :return: the output of the tool
        """
        pattern = re.compile(r"~~~(?:\w+)?\s*([\s\S]*?)\s*~~~")
        match = pattern.search(response)
        if match:
            output = PromptSynthesizerOutput(match.group(1))
            if output.is_valid_json:
                self.logger.print_log(f"Synthesized valid JSON prompt successfully")
            else:
                self.logger.print_log(f"Extracted prompt is not valid JSON.")
        else:
            self.logger.print_log(f"Synthesized prompt not found in output")
            output = None
        print(response)
        return output

    def get_bug_catogory(self, bug_type) -> BugCategory:
        """
        Get the bug category of the tool.
        :return: the bug category of the tool
        """
        prompt = f"""
            Please classify the bug type {bug_type} into one of the following categories based on its name:
            1. Numeric: Related to numeric values, such as integer overflow, divide-by-zero, etc.
            2. Pointer: Related to pointers, such as null pointer dereference, dangling pointer, double free, etc.
            3. Buffer: Related to buffer overflows, out-of-bounds reads/writes, etc.
            4. Pattern: Related to pattern matching bugs — given a specific pattern, detect bugs that match this pattern.
            
            Start your answer with 'Answer', then provide only the category name. Do not include any additional information. 
            For example: 'Answer': Numeric.
        """
        response, _, _ = self.model.infer(prompt, True)
        pattern = re.compile(r"Answer:\s*(\w+)")
        match = pattern.search(response)
        if match:
            category = match.group(1)
            if category == "Numeric":
                return BugCategory.NUMERIC
            elif category == "Pointer":
                return BugCategory.POINTER
            elif category == "Buffer":
                return BugCategory.BUFFER
            elif category == "Pattern":
                return BugCategory.PATTERN
            else:
                self.logger.print_log(f"Unknown bug type: {category}")
                return None
        else:
            self.logger.print_log(f"Failed to classify bug type {bug_type}")
            return None