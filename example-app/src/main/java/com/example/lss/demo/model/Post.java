package com.example.lss.demo.model;

/**
 * Post entity demonstrating @Owner feature
 */
public class Post {
    
    private Long id;
    private String title;
    private String content;
    private String createdBy; // User ID who created this post
    private Long createdAt;
    
    public Post() {
        this.createdAt = System.currentTimeMillis();
    }
    
    public Post(Long id, String title, String content, String createdBy) {
        this.id = id;
        this.title = title;
        this.content = content;
        this.createdBy = createdBy;
        this.createdAt = System.currentTimeMillis();
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    
    public Long getCreatedAt() { return createdAt; }
    public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }
}
