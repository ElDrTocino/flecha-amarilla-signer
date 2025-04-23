package org.flechaamarilla.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for XML processing requests
 * 
 * TODO: Change language convention to English in future refactorings
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class XmlRequestDTO {
    private String xmlContent;
}