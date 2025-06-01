#!/usr/bin/env python3
# AI Text Generator with Hugging Face and PyTorch Explicitly Used

# Import necessary libraries
import argparse
import torch
import logging
from transformers import GPT2LMHeadModel, GPT2Tokenizer

# Suppress all but error-level logging output
logging.basicConfig(level=logging.ERROR)

# Load pre-trained model and tokenizer
model_name = "gpt2"  # You can change this to a different model (e.g., "gpt2-medium", "gpt2-large")
tokenizer = GPT2Tokenizer.from_pretrained(model_name)
model = GPT2LMHeadModel.from_pretrained(model_name)

# Move model to GPU if available
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

# Function to generate text with improved settings
def generate_text(tokenizer, prompt, max_length=100):
    # Encode the prompt
    inputs = tokenizer.encode(prompt, return_tensors="pt").to(device)
    
    # Generate text with adjusted parameters to reduce repetition
    outputs = model.generate(
        inputs,
        max_length=max_length,
        num_return_sequences=1,
        temperature=0.9,            # Adds some randomness to avoid repetitive loops
        top_k=50,                   # Considers the top 50 words for each generation step
        top_p=0.9,                  # Considers a cumulative probability threshold for more variety
        repetition_penalty=1.2,     # Penalizes repeated phrases to promote diversity
        do_sample=True,             # Enables sampling mode to allow temperature and top_p to work
        pad_token_id=tokenizer.eos_token_id  # Sets the pad token to end-of-sequence token
    )
    
    # Decode and return the generated text
    generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return generated_text

# Main function to handle command-line arguments
def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Generate text using a pre-trained GPT-2 model.")
    parser.add_argument(
        "prompt",
        type=str,
        help="Enter the prompt you want the model to generate text from."
    )
    parser.add_argument(
        "--max_length",
        type=int,
        default=100,
        help="Maximum length of the generated text (default: 100 characters)."
    )
    
    args = parser.parse_args()  # Parse command-line arguments

    # Generate and print the text
    generated_text = generate_text(tokenizer, args.prompt, args.max_length)
    print("\nGenerated Text:\n", generated_text)

if __name__ == "__main__":
    main()  # Run the main function
