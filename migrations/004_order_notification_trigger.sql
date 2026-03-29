-- Habilita extensão pg_net (chamadas HTTP do banco)
CREATE EXTENSION IF NOT EXISTS pg_net;

-- Função que dispara a notificação quando status do pedido muda
CREATE OR REPLACE FUNCTION notify_order_status_change()
RETURNS TRIGGER AS $$
BEGIN
  -- Só dispara se o status realmente mudou
  IF OLD.status IS DISTINCT FROM NEW.status THEN
    PERFORM net.http_post(
      url     := 'https://api-24hrs.vercel.app/api/send-notification',
      headers := jsonb_build_object(
        'Content-Type',      'application/json',
        'x-webhook-secret',  'msd7yhuwn8237yucjbhsfctfd623gubsisdf334eff-43fsdfdd'
      ),
      body    := jsonb_build_object(
        'record',     row_to_json(NEW),
        'old_record', row_to_json(OLD)
      )
    );
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger na tabela orders
DROP TRIGGER IF EXISTS on_order_status_change ON orders;
CREATE TRIGGER on_order_status_change
  AFTER UPDATE ON orders
  FOR EACH ROW
  EXECUTE FUNCTION notify_order_status_change();

