package com.platzi.pizza.persitence.entity;


import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Setter
@Getter
@NoArgsConstructor
@Table(name = "order_item")
@IdClass(OrderItemId.class)
public class OrderItemEntity {

    @Id
    @Column(name = "id_item", nullable = false)
    private Integer idItem;

    @Id
    @Column(name = "id_order", nullable = false)
    private Integer idOrder;


    @Column(name = "id_pizza", nullable = false)
    private Integer idPizza;

    @Column(columnDefinition = "DECIMAL(2,1)", nullable = false)
    private Double quantity;

    @Column(columnDefinition = "DECIMAL(5,2)", nullable = false)
    private Double price;

    @OneToOne
    @JoinColumn(name = "id_pizza", referencedColumnName = "id_pizza", insertable = false, updatable = false)
    private PizzaEntity pizza;

    @ManyToOne
    @JoinColumn(name = "id_order", referencedColumnName = "id_order", insertable = false, updatable = false)
    @JsonIgnore

    private OrderEntity order;
}
