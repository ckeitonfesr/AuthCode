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
- "garbage": clearly fake/random (e.g. "aaaaaa", "1234567890", keyboard smash like "asdfgh")
- "suspicious": unusual but possibly real (e.g. very short name, odd phone pattern)
- "clean": looks like real user data
- For Brazilian phones: valid if 11 digits starting with DDD + 9
- For CPF: check obvious patterns (all same digit, sequential)
- For names: real names have normal first+last structure, not random chars
- Be conservative — lean "suspicious" over "garbage" when uncertain`;
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
