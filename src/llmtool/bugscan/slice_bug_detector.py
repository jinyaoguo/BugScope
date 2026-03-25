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

class SliceBugDetectorInput(LLMToolInput):
    def __init__(self, buggy_construct_str: str, single_function_str: str, function_name: str = "") -> None:
        """
        :param buggy_construct_str: the string indicating the buggy construct
        :param single_function_str: the string indicating the single function
        """
        self.buggy_construct_str = buggy_construct_str
        self.single_function_str = single_function_str
        self.function_name = function_name
        return

    def __hash__(self) -> int:
        return hash((self.buggy_construct_str, self.single_function_str))
        

class SliceBugDetectorOutput(LLMToolOutput):
    def __init__(self, is_buggy: bool, explanation_str: str) -> None:
        """
        :param is_buggy: whether the construct is buggy. The construct can be a specific expression
        :param explanation_str: the string explaining the proof of concept
        """
        self.is_buggy = is_buggy
        self.explanation_str = explanation_str
        return
    
    def __str__(self):
        return f"Is buggy: {self.is_buggy} \nExplanation: {self.explanation_str}"


class SliceBugDetector(LLMTool):
    def __init__(self, bug_type: str, model_name: str, temperature: float, language: str, max_query_num: int, logger: Logger, prompt_file: str = "") -> None:
        """
        :param bug_type: the type of bug to detect
        :param model_name: the model name
        :param temperature: the temperature
        :param language: the programming language
        :param max_query_num: the maximum number of queries if the model fails
        :param logger: the logger
        """
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self.bug_type = bug_type
        if prompt_file != "":
            self.prompt_file = prompt_file
        else:
            self.prompt_file = f"{BASE_PATH}/prompt/{language}/bugscan/{bug_type}_slice_bug_detector.json"
        return

    def _get_prompt(self, input: SliceBugDetectorInput) -> str:
        """
        :param input: the input of intra-procedural detector
        :return: the prompt string
        """
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)
        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules"])
        prompt += "\n" + "\n".join(prompt_template_dict.get("analysis_examples", []))
        prompt += "\n" + "".join(prompt_template_dict["meta_prompts"])
        prompt = prompt.replace("<ANSWER>", "\n".join(prompt_template_dict["answer_format"]))
        prompt = prompt.replace("<QUESTION>", prompt_template_dict["question_template"])
        prompt = prompt.replace("<FUNCTION>", input.single_function_str)
        prompt = prompt.replace("<SEED_NAME>", input.buggy_construct_str)
        prompt = prompt.replace("<FUNCTION_NAME>", input.function_name)

        return prompt

    def _parse_response(self, response: str, input: SliceBugDetectorInput) -> SliceBugDetectorOutput:
        """
        :param response: the string response from the model (expected in JSON format)
        :return: the output of intra-procedural detector
        """
        try:
            # Extract JSON block
            json_match = re.search(r'```json(.*)```', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1).strip()
            else:
                # Fallback: try parse whole response as JSON
                json_str = response.strip()

            # Parse JSON
            data = json.loads(json_str)

            answer_str = data.get("Answer", "").strip()
            poc_str = data.get("PoC", "").strip()

            # Construct output
            output = SliceBugDetectorOutput(answer_str == "Yes", poc_str)
            self.logger.print_log("Output of intra_detector:\n", str(output))

        except Exception as e:
            self.logger.print_log(f"Failed to parse JSON response: {str(e)}")
            output = None

        return output
