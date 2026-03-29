-- Função transacional para criar pedido + itens + limpar carrinho atomicamente.
-- Usar SECURITY DEFINER permite que o cliente anon chame a função, mas a execução
-- ocorre com os privilégios do owner (postgres), garantindo acesso às tabelas.

CREATE OR REPLACE FUNCTION create_order_with_items(
  p_user_id        UUID,
  p_status         TEXT,
  p_total          NUMERIC,
  p_payment_method TEXT,
  p_address        TEXT,
  p_items          JSONB
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_order_id UUID;
BEGIN
  -- 1. Cria o pedido
  INSERT INTO orders (user_id, status, total, payment_method, address)
  VALUES (p_user_id, p_status, p_total, p_payment_method, p_address)
  RETURNING id INTO v_order_id;

  -- 2. Insere os itens do pedido
  INSERT INTO order_items (order_id, product_id, name, quantity, price)
  SELECT
    v_order_id,
    (item->>'product_id')::UUID,
    item->>'name',
    (item->>'quantity')::INTEGER,
    (item->>'price')::NUMERIC
  FROM jsonb_array_elements(p_items) AS item;

  -- 3. Limpa o carrinho do usuário
  DELETE FROM cart_items WHERE user_id = p_user_id;

  RETURN v_order_id;
END;
$$;

-- Permite que o role authenticated (usuário logado) chame a função
GRANT EXECUTE ON FUNCTION create_order_with_items(UUID, TEXT, NUMERIC, TEXT, TEXT, JSONB)
  TO authenticated;
