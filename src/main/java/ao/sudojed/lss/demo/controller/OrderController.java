package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.LazySecured;
import ao.sudojed.lss.annotation.Owner;
import ao.sudojed.lss.annotation.RateLimit;
import ao.sudojed.lss.core.LazyUser;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Controller de pedidos.
 * 
 * Demonstra o uso de:
 * - @Owner para verificação de propriedade do recurso
 * - @RateLimit para limitar requisições
 * - Combinação de anotações de segurança
 */
@RestController
@RequestMapping("/api")
public class OrderController {

    // Simula banco de dados de pedidos
    private final Map<String, List<Map<String, Object>>> ordersByUser = new ConcurrentHashMap<>();

    public OrderController() {
        // Dados de exemplo
        initializeSampleData();
    }

    private void initializeSampleData() {
        ordersByUser.put("user-1", List.of(
            Map.of("orderId", "ORD-001", "product", "Notebook", "total", 2500.00, "status", "DELIVERED"),
            Map.of("orderId", "ORD-002", "product", "Mouse", "total", 150.00, "status", "SHIPPED")
        ));
        ordersByUser.put("user-2", List.of(
            Map.of("orderId", "ORD-003", "product", "Teclado", "total", 300.00, "status", "PENDING")
        ));
    }

    /**
     * Lista pedidos do usuário logado.
     * 
     * @LazySecured - Requer autenticação
     * @RateLimit - Limita a 10 requisições por minuto
     * 
     * Uso: GET /api/orders
     */
    @LazySecured
    @RateLimit(requests = 10, window = 60)
    @GetMapping("/orders")
    public Map<String, Object> getMyOrders(LazyUser user) {
        List<Map<String, Object>> orders = ordersByUser.getOrDefault(user.getId(), List.of());
        
        return Map.of(
            "userId", user.getId(),
            "username", user.getUsername(),
            "totalOrders", orders.size(),
            "orders", orders
        );
    }

    /**
     * Cria um novo pedido.
     * 
     * @LazySecured - Requer autenticação
     * @RateLimit - Limita a 5 pedidos por minuto (anti-spam)
     * 
     * Uso: POST /api/orders
     * Body: { "product": "Headphone", "quantity": 1, "price": 200.00 }
     */
    @LazySecured
    @RateLimit(requests = 5, window = 60)
    @PostMapping("/orders")
    public Map<String, Object> createOrder(
            LazyUser user,
            @RequestBody Map<String, Object> orderData) {
        
        String orderId = "ORD-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        
        Map<String, Object> newOrder = new HashMap<>();
        newOrder.put("orderId", orderId);
        newOrder.put("product", orderData.get("product"));
        newOrder.put("quantity", orderData.getOrDefault("quantity", 1));
        newOrder.put("price", orderData.get("price"));
        newOrder.put("total", calculateTotal(orderData));
        newOrder.put("status", "PENDING");
        newOrder.put("createdAt", LocalDateTime.now().toString());
        newOrder.put("userId", user.getId());

        // Adiciona ao "banco"
        ordersByUser.computeIfAbsent(user.getId(), k -> new ArrayList<>());
        List<Map<String, Object>> userOrders = new ArrayList<>(ordersByUser.get(user.getId()));
        userOrders.add(newOrder);
        ordersByUser.put(user.getId(), userOrders);

        return Map.of(
            "message", "Pedido criado com sucesso!",
            "order", newOrder
        );
    }

    /**
     * Obtém pedidos de um usuário específico.
     * 
     * @Owner - Verifica se o usuário está acessando seus próprios dados
     *          Admins podem acessar dados de qualquer usuário (adminBypass = true)
     * 
     * Uso: GET /api/users/{userId}/orders
     * 
     * Se userId != usuário logado e não for admin → 403 Forbidden
     */
    @LazySecured
    @Owner(field = "userId", adminBypass = true)
    @GetMapping("/users/{userId}/orders")
    public Map<String, Object> getUserOrders(@PathVariable String userId) {
        List<Map<String, Object>> orders = ordersByUser.getOrDefault(userId, List.of());
        
        return Map.of(
            "userId", userId,
            "totalOrders", orders.size(),
            "orders", orders
        );
    }

    /**
     * Cancela um pedido.
     * 
     * Demonstra lógica de negócio com verificação de propriedade.
     * 
     * Uso: DELETE /api/orders/{orderId}
     */
    @LazySecured
    @DeleteMapping("/orders/{orderId}")
    public Map<String, Object> cancelOrder(
            LazyUser user,
            @PathVariable String orderId) {
        
        // Busca o pedido
        List<Map<String, Object>> userOrders = ordersByUser.getOrDefault(user.getId(), List.of());
        
        Optional<Map<String, Object>> orderOpt = userOrders.stream()
            .filter(o -> orderId.equals(o.get("orderId")))
            .findFirst();

        if (orderOpt.isEmpty()) {
            // Se for admin, pode cancelar pedido de qualquer usuário
            if (user.isAdmin()) {
                for (var entry : ordersByUser.entrySet()) {
                    Optional<Map<String, Object>> found = entry.getValue().stream()
                        .filter(o -> orderId.equals(o.get("orderId")))
                        .findFirst();
                    if (found.isPresent()) {
                        List<Map<String, Object>> updated = new ArrayList<>(entry.getValue());
                        updated.remove(found.get());
                        ordersByUser.put(entry.getKey(), updated);
                        return Map.of(
                            "message", "Pedido cancelado pelo admin",
                            "orderId", orderId
                        );
                    }
                }
            }
            
            return Map.of(
                "error", "ORDER_NOT_FOUND",
                "message", "Pedido não encontrado ou não pertence a você"
            );
        }

        // Remove o pedido
        List<Map<String, Object>> updated = new ArrayList<>(userOrders);
        updated.remove(orderOpt.get());
        ordersByUser.put(user.getId(), updated);

        return Map.of(
            "message", "Pedido cancelado com sucesso",
            "orderId", orderId
        );
    }

    private double calculateTotal(Map<String, Object> orderData) {
        Object priceObj = orderData.get("price");
        Object quantityObj = orderData.getOrDefault("quantity", 1);
        
        double price = priceObj instanceof Number ? ((Number) priceObj).doubleValue() : 0;
        int quantity = quantityObj instanceof Number ? ((Number) quantityObj).intValue() : 1;
        
        return price * quantity;
    }
}
