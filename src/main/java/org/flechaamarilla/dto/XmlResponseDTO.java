package org.flechaamarilla.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * DTO for XML processing responses
 * 
 * TODO: Change language convention to English in future refactorings
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class XmlResponseDTO {
    private String xmlContent;
    private boolean valid;
    private String uuid;
    private List<String> errors = new ArrayList<>();
}