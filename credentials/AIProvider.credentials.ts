/**
 * AI Provider Credentials
 *
 * Credentials for AI services (Claude, OpenAI) used in
 * smart contract generation
 */

import {
  ICredentialType,
  INodeProperties,
  ICredentialTestRequest,
} from "n8n-workflow";

export class AIProvider implements ICredentialType {
  name = "aiProvider";
  displayName = "AI Provider";
  documentationUrl = "https://docs.anthropic.com/en/api/getting-started";
  icon = "file:ai.svg" as const;

  properties: INodeProperties[] = [
    {
      displayName: "Provider",
      name: "provider",
      type: "options",
      options: [
        {
          name: "Claude (Anthropic)",
          value: "claude",
          description: "Use Claude AI for contract generation",
        },
        {
          name: "GPT-4 (OpenAI)",
          value: "openai",
          description: "Use OpenAI GPT-4 for contract generation",
        },
      ],
      default: "claude",
      description: "Select the AI provider to use",
    },

    // Claude Configuration
    {
      displayName: "Anthropic API Key",
      name: "anthropicApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      displayOptions: {
        show: {
          provider: ["claude"],
        },
      },
      default: "",
      placeholder: "sk-ant-...",
      description: "Your Anthropic API key",
      required: true,
    },
    {
      displayName: "Claude Model",
      name: "claudeModel",
      type: "options",
      displayOptions: {
        show: {
          provider: ["claude"],
        },
      },
      options: [
        {
          name: "Claude 3.5 Sonnet (Recommended)",
          value: "claude-3-5-sonnet-20241022",
        },
        {
          name: "Claude 3 Opus",
          value: "claude-3-opus-20240229",
        },
        {
          name: "Claude 3 Sonnet",
          value: "claude-3-sonnet-20240229",
        },
        {
          name: "Claude 3 Haiku",
          value: "claude-3-haiku-20240307",
        },
      ],
      default: "claude-3-5-sonnet-20241022",
      description: "Claude model to use for generation",
    },

    // OpenAI Configuration
    {
      displayName: "OpenAI API Key",
      name: "openaiApiKey",
      type: "string",
      typeOptions: {
        password: true,
      },
      displayOptions: {
        show: {
          provider: ["openai"],
        },
      },
      default: "",
      placeholder: "sk-...",
      description: "Your OpenAI API key",
      required: true,
    },
    {
      displayName: "OpenAI Model",
      name: "openaiModel",
      type: "options",
      displayOptions: {
        show: {
          provider: ["openai"],
        },
      },
      options: [
        {
          name: "GPT-4 Turbo (Recommended)",
          value: "gpt-4-turbo-preview",
        },
        {
          name: "GPT-4",
          value: "gpt-4",
        },
        {
          name: "GPT-4 32K",
          value: "gpt-4-32k",
        },
        {
          name: "GPT-3.5 Turbo",
          value: "gpt-3.5-turbo",
        },
      ],
      default: "gpt-4-turbo-preview",
      description: "OpenAI model to use for generation",
    },

    // Common Settings
    {
      displayName: "Max Tokens",
      name: "maxTokens",
      type: "number",
      default: 4096,
      description: "Maximum number of tokens in the response",
    },
    {
      displayName: "Temperature",
      name: "temperature",
      type: "number",
      default: 0.3,
      typeOptions: {
        minValue: 0,
        maxValue: 2,
        numberPrecision: 2,
      },
      description:
        "Controls randomness. Lower values are more deterministic (recommended for code generation).",
    },
  ];

  // Note: Test is defined but may need different implementation per provider
  test: ICredentialTestRequest = {
    request: {
      baseURL: "https://api.anthropic.com",
      url: "/v1/messages",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "={{$credentials.anthropicApiKey}}",
        "anthropic-version": "2023-06-01",
      },
      body: {
        model: "claude-3-haiku-20240307",
        max_tokens: 10,
        messages: [{ role: "user", content: "Hi" }],
      },
    },
  };
}
