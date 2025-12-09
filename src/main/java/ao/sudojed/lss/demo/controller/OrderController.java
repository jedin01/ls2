package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.LazySecured;
import ao.sudojed.lss.annotation.RateLimit;
import ao.sudojed.lss.facade.Auth;
import ao.sudojed.lss.facade.Guard;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Controller de pedidos demonstrando Auth e Guard facades.
 * 
 * Demonstra:
 * - Auth.id(), Auth.username() para obter dados do usuario
 * - Guard.owner() para verificar propriedade de recursos
 * - Guard.authenticated() para exigir login
 * - @RateLimit para limitar requisicoes
 * 
 * Comparacao com Laravel:
 * - Auth.id()        -> auth()->id()
 * - Guard.owner(id)  -> $this->authorize('view', $resource)
 * - Auth.isAdmin()   -> auth()->user()->isAdmin()
 */
@RestController
@RequestMapping("/api")
public class OrderController {

    // Simula banco de dados de pedidos
    private final Map<String, List<Map<String, Object>>> ordersByUser = new ConcurrentHashMap<>();

    public OrderController() {
        initializeSampleData();
    }

    private void initializeSampleData() {
        ordersByUser.put("user-1", new ArrayList<>(List.of(
            Map.of("orderId", "ORD-001", "product", "Notebook", "total", 2500.00, "status", "DELIVERED"),
            Map.of("orderId", "ORD-002", "product", "Mouse", "total", 150.00, "status", "SHIPPED")
        )));
        ordersByUser.put("user-2", new ArrayList<>(List.of(
            Map.of("orderId", "ORD-003", "product", "Teclado", "total", 300.00, "status", "PENDING")
        )));
    }

    /**
     * Lista pedidos do usuario logado.
     * 
     * Usa Auth.id() e Auth.username() - sem parametro LazyUser!
     */
    @LazySecured
    @RateLimit(requests = 10, window = 60)
    @GetMapping("/orders")
    public Map<String, Object> getMyOrders() {
        // Usa Auth facade ao inves de parametro LazyUser
        String userId = Auth.id();
        String username = Auth.username();
        
        List<Map<String, Object>> orders = ordersByUser.getOrDefault(userId, List.of());
        
        return Map.of(
            "userId", userId,
            "username", username,
            "totalOrders", orders.size(),
            "orders", orders
        );
    }

    /**
     * Cria um novo pedido.
     * 
     * Demonstra Guard.authenticated() para verificacao imperativa.
     */
    @RateLimit(requests = 5, window = 60)
    @PostMapping("/orders")
    public Map<String, Object> createOrder(@RequestBody Map<String, Object> orderData) {
        // Verificacao imperativa de autenticacao
        Guard.authenticated();
        
        String orderId = "ORD-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        
        Map<String, Object> newOrder = new HashMap<>();
        newOrder.put("orderId", orderId);
        newOrder.put("product", orderData.get("product"));
        newOrder.put("quantity", orderData.getOrDefault("quantity", 1));
        newOrder.put("price", orderData.get("price"));
        newOrder.put("total", calculateTotal(orderData));
        newOrder.put("status", "PENDING");
        newOrder.put("createdAt", LocalDateTime.now().toString());
        newOrder.put("userId", Auth.id());  // Auth facade!

        // Adiciona ao "banco"
        ordersByUser.computeIfAbsent(Auth.id(), k -> new ArrayList<>());
        List<Map<String, Object>> userOrders = new ArrayList<>(ordersByUser.get(Auth.id()));
        userOrders.add(newOrder);
        ordersByUser.put(Auth.id(), userOrders);

        return Map.of(
            "message", "Pedido criado com sucesso!",
            "order", newOrder,
            "createdBy", Auth.username()
        );
    }

    /**
     * Obtem pedidos de um usuario especifico.
     * 
     * Demonstra Guard.owner() - verifica se usuario eh dono do recurso.
     * Admin tem bypass automatico.
     * 
     * Equivalente Laravel: $this->authorize('view', $user);
     */
    @GetMapping("/users/{userId}/orders")
    public Map<String, Object> getUserOrders(@PathVariable String userId) {
        // Exige autenticacao primeiro
        Guard.authenticated();
        
        // Verifica se eh o dono OU admin (admin tem bypass automatico)
        Guard.owner(userId);
        
        List<Map<String, Object>> orders = ordersByUser.getOrDefault(userId, List.of());
        
        return Map.of(
            "userId", userId,
            "totalOrders", orders.size(),
            "orders", orders,
            "accessedBy", Auth.username(),
            "isOwner", userId.equals(Auth.id()),
            "isAdmin", Auth.isAdmin()
        );
    }

    /**
     * Cancela um pedido.
     * 
     * Demonstra logica condicional com Auth.isAdmin().
     */
    @DeleteMapping("/orders/{orderId}")
    public Map<String, Object> cancelOrder(@PathVariable String orderId) {
        Guard.authenticated();
        
        String userId = Auth.id();
        
        // Busca o pedido do usuario atual
        List<Map<String, Object>> userOrders = ordersByUser.getOrDefault(userId, new ArrayList<>());
        
        Optional<Map<String, Object>> orderOpt = userOrders.stream()
            .filter(o -> orderId.equals(o.get("orderId")))
            .findFirst();

        if (orderOpt.isEmpty()) {
            // Se for admin, pode cancelar pedido de qualquer usuario
            if (Auth.isAdmin()) {
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
                            "orderId", orderId,
                            "cancelledBy", Auth.username()
                        );
                    }
                }
            }
            
            return Map.of(
                "error", "ORDER_NOT_FOUND",
                "message", "Pedido nao encontrado ou nao pertence a voce"
            );
        }

        // Remove o pedido
        List<Map<String, Object>> updated = new ArrayList<>(userOrders);
        updated.remove(orderOpt.get());
        ordersByUser.put(userId, updated);

        return Map.of(
            "message", "Pedido cancelado com sucesso",
            "orderId", orderId,
            "cancelledBy", Auth.username()
        );
    }

    /**
     * Endpoint que requer ADMIN ou MANAGER para ver todos os pedidos.
     * 
     * Demonstra Guard.anyRole().
     */
    @GetMapping("/orders/all")
    public Map<String, Object> getAllOrders() {
        // Apenas ADMIN ou MANAGER podem ver todos os pedidos
        Guard.anyRole("ADMIN", "MANAGER");
        
        List<Map<String, Object>> allOrders = new ArrayList<>();
        for (var entry : ordersByUser.entrySet()) {
            for (var order : entry.getValue()) {
                Map<String, Object> orderWithOwner = new HashMap<>(order);
                orderWithOwner.put("ownerId", entry.getKey());
                allOrders.add(orderWithOwner);
            }
        }
        
        return Map.of(
            "totalOrders", allOrders.size(),
            "orders", allOrders,
            "requestedBy", Auth.username(),
            "userRole", Auth.user().getRoles()
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
