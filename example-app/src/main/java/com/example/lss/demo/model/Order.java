package com.example.lss.demo.model;

/**
 * Order entity demonstrating @Owner with path variables
 */
public class Order {
    
    private Long id;
    private String userId;
    private String productName;
    private Double amount;
    private String status;
    private Long createdAt;
    
    public Order() {
        this.createdAt = System.currentTimeMillis();
        this.status = "PENDING";
    }
    
    public Order(Long id, String userId, String productName, Double amount) {
        this.id = id;
        this.userId = userId;
        this.productName = productName;
        this.amount = amount;
        this.createdAt = System.currentTimeMillis();
        this.status = "PENDING";
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public String getProductName() { return productName; }
    public void setProductName(String productName) { this.productName = productName; }
    
    public Double getAmount() { return amount; }
    public void setAmount(Double amount) { this.amount = amount; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }
}
