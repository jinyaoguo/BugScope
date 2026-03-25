from os import path
import json
from llmtool.LLM_utils import *
from llmtool.LLM_tool import *
from memory.syntactic.function import *
from memory.syntactic.value import *
from memory.syntactic.api import *
BASE_PATH = Path(__file__).resolve().parent.parent.parent

class PromptOptimizerInput(LLMToolInput):
    def __init__(self, language: str, bug_type: str, feedback_file_name: str) -> None:
        """
        :param language: the programming language
        :param bug_type: the type of bug
        :param feedback_file_name: the name of the feedback file
        """
        self.bug_type = bug_type
        self.feedback_file_path = f"{BASE_PATH}/src/prompt/{language}/Synthesis/feedback/{bug_type}/{feedback_file_name}.json"
        return
    
    def __hash__(self) -> int:
        return hash((self.bug_type, self.feedback_file_path))


class PromptOptimizerOutput(LLMToolOutput):
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


class PromptOptimizer(LLMTool):
    def __init__(self, model_name: str, temperature: float, language: str, bug_type: str, max_query_num: int, logger: Logger) -> None:
        super().__init__(model_name, temperature, language, max_query_num, logger)
        self.bug_type = bug_type
        self.prompt_file = f"{BASE_PATH}/src/prompt/{language}/Synthesis/detection_prompt_optimizer.json"
        return

    def _get_prompt(self, input: PromptOptimizerInput) -> str:
        """
        :param input: the input of prompt Optimizer
        :return: the prompt string
        """
        with open(self.prompt_file, "r") as f:
            prompt_template_dict = json.load(f)
        
        with open(input.feedback_file_path, "r") as f:
            feedback_info = json.load(f)
        
        prompt = prompt_template_dict["task"]
        prompt += "\n" + "\n".join(prompt_template_dict["analysis_rules"])
        prompt += "\n" + "\n".join(prompt_template_dict["meta_prompts"])
        prompt = prompt.replace("<ANSWER>", "\n".join(prompt_template_dict["answer_format"]))
        prompt = prompt.replace("<BUG_TYPE>", input.bug_type)
        current_prompt_str = feedback_info["current_prompt"]
        prompt = prompt.replace("<DETECTION_PROMPT>", current_prompt_str)

        fp_examples = [example for example in feedback_info["examples"] if example["label"] == "FP"]
        fn_examples = [example for example in feedback_info["examples"] if example["label"] == "FN"]

        fp_example_str = ""
        for i, example in enumerate(fp_examples):
            fp_example_str += f"Example {i + 1}:\n"
            fp_example_str += f"Code: {example['code']}\n"
            fp_example_str += f"Original Report (Wrong): {example['report']}\n"
            fp_example_str += f"Description: {example['description']}\n"
            fp_example_str += f"\n"
        prompt = prompt.replace("<FALSE_POSITIVES>", fp_example_str)

        fn_example_str = ""
        for i, example in enumerate(fn_examples):
            fn_example_str += f"Example {i + 1}:\n"
            fn_example_str += f"Code: {example['code']}\n"
            fn_example_str += f"Original Report (Wrong): {example['report']}\n"
            fn_example_str += f"Description: {example['description']}\n"
            fn_example_str += f"\n"
        prompt = prompt.replace("<FALSE_NEGATIVES>", fn_example_str)
    
        return prompt

    def _parse_response(self, response: str, audit_request_formulator_input: PromptOptimizerInput) -> PromptOptimizerOutput:
        """
        Parse the response from the model.
        :param response: the response from the model
        :param audit_request_formulator_input: the audit_request_formulator_input of the tool
        :return: the output of the tool
        """
        pattern = re.compile(r"~~~(?:\w+)?\s*([\s\S]*?)\s*~~~")
        match = pattern.search(response)
        if match:
            output = PromptOptimizerOutput(match.group(1))
            if output.is_valid_json:
                self.logger.print_log(f"Optimize valid prompt successfully")
            else:
                self.logger.print_log(f"Extracted prompt is not valid JSON.")
        else:
            self.logger.print_log(f"Optimized prompt not found in output")
            output = None
        print(response)
        return output
