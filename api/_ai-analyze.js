const supabase = require('./_supabase');
const GEMINI_API_URL =
  'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent';
async function analyzeData(payload) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) { console.error('[ai-analyze] GEMINI_API_KEY não configurado'); return; }
  const { userId, trigger, fields } = payload;
  const fieldLines = Object.entries(fields)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `  ${k}: "${v}"`)
    .join('\n');
  const prompt = `You are a fraud and data quality analyst for a Brazilian food delivery app.
Analyze the following user-submitted data and determine if it looks like garbage, fake, or suspicious input.
Trigger: ${trigger}
Fields:
${fieldLines}
Respond ONLY in valid JSON (no markdown, no backticks) with this exact shape:
{
  "verdict": "clean" | "suspicious" | "garbage",
  "confidence": 0-100,
  "signals": ["signal1", "signal2"],
  "reasoning": "short explanation in Portuguese"
}
Rules:
- "garbage": clearly fake/random — keyboard smash (asdfgh, zxcvbn, qwerty, xksjdhf), repeated chars (aaaa), sequential numbers, nonsense strings, any name that is obviously not a real human name
- "suspicious": unusual but could be real — very short name (1 word), odd phone pattern, nickname-style name
- "clean": looks like a real Brazilian person's name and valid contact info
- For names: if EITHER first or last name looks like keyboard smash or random chars → "garbage"
- For Brazilian phones: valid if 11 digits starting with DDD (11-99) + 9
- For CPF: garbage if all same digit or sequential (111.111.111-11, 123.456.789-09)
- Do NOT be conservative with names — if it looks like keyboard smash, mark as "garbage"`;
  let verdict = 'clean';
  let confidence = 50;
  let signals = [];
  let reasoning = '';
  try {
    const res = await fetch(`${GEMINI_API_URL}?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,
          maxOutputTokens: 800,
          thinkingConfig: {
            thinkingBudget: 0,
          },
        },
      }),
    });
    if (!res.ok) {
      const errBody = await res.text();
      console.error('[ai-analyze] Gemini API error:', res.status, errBody.slice(0, 300));
      return;
    }
    const data = await res.json();
    const parts = data?.candidates?.[0]?.content?.parts ?? [];
    const text = parts.find(p => p.text && !p.thought)?.text;
    if (!text) return;
    const raw = text.replace(/^```json\s*/i, '').replace(/\s*```$/, '').trim();
    const parsed = JSON.parse(raw);
    verdict    = parsed.verdict    ?? 'clean';
    confidence = parsed.confidence ?? 50;
    signals    = parsed.signals    ?? [];
    reasoning  = parsed.reasoning  ?? '';
  } catch (err) {
    console.error('[ai-analyze] parse/fetch error:', err.message);
    return;
  }
  if (verdict === 'clean' && confidence >= 70) return;
  const { error: insertErr } = await supabase.from('ai_flags').insert({
    user_id:    userId,
    trigger,
    fields:     fields,
    verdict,
    confidence,
    signals,
    reasoning,
  });
  if (insertErr) {
    console.error('[ai-analyze] DB insert error:', insertErr.message);
  }
}
module.exports = { analyzeData };
