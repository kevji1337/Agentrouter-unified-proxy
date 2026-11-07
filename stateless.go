package main

import (
	"encoding/json"
	"strings"
)

func isForeignAzureResourceError(status int, body []byte) bool {
	if status != 400 {
		return false
	}
	message := strings.ToLower(string(body))
	return strings.Contains(message, "created under a different") &&
		strings.Contains(message, "azure openai resource")
}

// sanitizeResourceBoundState converts a Responses request to a self-contained,
// stateless request suitable for an upstream that load-balances independent
// Azure OpenAI resources. Human/model content and call_id correlations remain;
// only server-owned references and encrypted reasoning are removed.
func sanitizeResourceBoundState(raw []byte) ([]byte, bool, error) {
	request, err := decodeObject(raw)
	if err != nil {
		return nil, false, err
	}
	changed := false
	if store, exists := request["store"]; !exists || store != false {
		request["store"] = false
		changed = true
	}
	for _, key := range []string{"previous_response_id", "include"} {
		if _, exists := request[key]; exists {
			delete(request, key)
			changed = true
		}
	}

	if input, ok := request["input"].([]any); ok {
		cleaned := make([]any, 0, len(input))
		for _, rawItem := range input {
			item, ok := rawItem.(map[string]any)
			if !ok {
				cleaned = append(cleaned, rawItem)
				continue
			}
			itemType, _ := item["type"].(string)
			itemID, _ := item["id"].(string)
			if itemType == "reasoning" || itemType == "item_reference" ||
				strings.HasPrefix(itemID, "rs_") || item["encrypted_content"] != nil {
				changed = true
				continue
			}
			if _, exists := item["id"]; exists {
				delete(item, "id")
				changed = true
			}
			if content, ok := item["content"].([]any); ok {
				cleanedContent := make([]any, 0, len(content))
				for _, rawPart := range content {
					part, ok := rawPart.(map[string]any)
					if !ok {
						cleanedContent = append(cleanedContent, rawPart)
						continue
					}
					partType, _ := part["type"].(string)
					partID, _ := part["id"].(string)
					if partType == "reasoning" || strings.HasPrefix(partID, "rs_") || part["encrypted_content"] != nil {
						changed = true
						continue
					}
					if _, exists := part["id"]; exists {
						delete(part, "id")
						changed = true
					}
					cleanedContent = append(cleanedContent, part)
				}
				item["content"] = cleanedContent
			}
			cleaned = append(cleaned, item)
		}
		request["input"] = cleaned
	}

	if !changed {
		return raw, false, nil
	}
	encoded, err := json.Marshal(request)
	return encoded, true, err
}
