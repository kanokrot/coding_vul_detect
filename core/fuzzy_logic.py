import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
from core.data_processor import discretize_data

# ── Build the fuzzy system ONCE at module load time ───────────────────────────
# Rebuilding Antecedent/Consequent/Rule/ControlSystem objects on every call
# is expensive — with large repos this ran 75+ times unnecessarily.

def _build_fuzzy_system():
    """Construct and return a compiled fuzzy ControlSystem."""

    # ── Antecedents & Consequent ──────────────────────────────────────────────
    ai_conf  = ctrl.Antecedent(np.arange(0, 1.01, 0.01), 'ai_conf')
    code_ent = ctrl.Antecedent(np.arange(0, 8.51, 0.01), 'code_ent')
    risk     = ctrl.Consequent(np.arange(0, 101,  1),    'risk')

    # ── ai_conf membership functions ─────────────────────────────────────────
    # Non-overlapping regions with clean transition zones
    ai_conf['low']    = fuzz.trimf(ai_conf.universe, [0.0,  0.0,  0.45])
    ai_conf['medium'] = fuzz.trimf(ai_conf.universe, [0.35, 0.5,  0.65])
    ai_conf['high']   = fuzz.trimf(ai_conf.universe, [0.55, 1.0,  1.0 ])

    # ── code_ent membership functions ────────────────────────────────────────
    # FIX: tightened overlap between normal/suspicious (was 5.0–6.0 ambiguous band)
    code_ent['normal']     = fuzz.trapmf(code_ent.universe, [0.0, 0.0,  4.5, 5.5])
    code_ent['suspicious'] = fuzz.trimf(code_ent.universe,  [5.0, 6.25, 7.0     ])
    code_ent['high']       = fuzz.trimf(code_ent.universe,  [6.5, 8.5,  8.5     ])

    # ── risk output membership functions ─────────────────────────────────────
    # FIX: removed overlapping warning/high band (was 50–70 ambiguous)
    # FIX: aligned peaks with severity thresholds used in scoring below
    #   safe     → centre  20  → severity "Low"      (< 40)
    #   warning  → centre  50  → severity "Medium"   (40–59)
    #   high     → centre  70  → severity "High"     (60–79)
    #   critical → centre  90  → severity "Critical" (≥ 80)
    risk['safe']     = fuzz.trimf(risk.universe, [0,  20,  40])
    risk['warning']  = fuzz.trimf(risk.universe, [30, 50,  60])
    risk['high']     = fuzz.trimf(risk.universe, [55, 70,  80])
    risk['critical'] = fuzz.trimf(risk.universe, [75, 90, 100])

    # ── Rules ─────────────────────────────────────────────────────────────────
    rules = [
        ctrl.Rule(ai_conf['high']   & code_ent['high'],       risk['critical']),
        ctrl.Rule(ai_conf['high']   & code_ent['suspicious'],  risk['critical']),
        ctrl.Rule(ai_conf['high']   & code_ent['normal'],      risk['high']),
        ctrl.Rule(ai_conf['medium'] & code_ent['high'],        risk['high']),
        ctrl.Rule(ai_conf['medium'] & code_ent['suspicious'],  risk['warning']),
        ctrl.Rule(ai_conf['medium'] & code_ent['normal'],      risk['warning']),
        ctrl.Rule(ai_conf['low']    & code_ent['high'],        risk['warning']),
        ctrl.Rule(ai_conf['low']    & code_ent['suspicious'],  risk['safe']),
        ctrl.Rule(ai_conf['low']    & code_ent['normal'],      risk['safe']),
    ]

    return ctrl.ControlSystem(rules)


# ── Module-level singleton — built once, reused for every call ────────────────
_FUZZY_CTRL = _build_fuzzy_system()


def _fallback_score(ai_prob: float, entropy: float) -> float:
    """
    Manual score used when the fuzzy engine raises an exception.
    FIX: uses the same severity breakpoints as the fuzzy output so that
    fallback results are consistent with normal results.
      - ai_prob contributes 70 % of the score
      - entropy (normalised to 0–1 over a 0–8.5 range) contributes 30 %
    """
    norm_entropy = min(entropy / 8.5, 1.0)
    return round((ai_prob * 0.7 + norm_entropy * 0.3) * 100, 2)


def _score_to_severity(score: float) -> str:
    """
    FIX: severity thresholds now align with the peaks of the fuzzy
    risk membership functions (safe≈20, warning≈50, high≈70, critical≈90).
    """
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def calculate_fuzzy_risk(ai_prob: float, entropy: float):
    """
    Compute fuzzy risk score and return (risk_score, severity, prob_label, entropy_label).

    Parameters
    ----------
    ai_prob  : float  Vulnerability probability from analyzer (0.0 – 1.0)
    entropy  : float  Shannon entropy of the source file

    Returns
    -------
    (float, str, str, str)
        risk_score     — 0–100 rounded to 2 dp
        severity       — "Low" | "Medium" | "High" | "Critical"
        prob_label     — discretised label from data_processor
        entropy_label  — discretised label from data_processor
    """
    # Clamp inputs to valid universe ranges to avoid skfuzzy edge-case errors
    ai_prob_clamped  = float(np.clip(ai_prob,  0.0, 1.0))
    entropy_clamped  = float(np.clip(entropy,  0.0, 8.5))

    try:
        # FIX: reuse the module-level singleton instead of rebuilding each call
        sim = ctrl.ControlSystemSimulation(_FUZZY_CTRL)
        sim.input['ai_conf']  = ai_prob_clamped
        sim.input['code_ent'] = entropy_clamped
        sim.compute()
        final_score = round(sim.output['risk'], 2)

    except Exception as e:
        print(f"⚠️ Fuzzy Error: {e} — using fallback scorer")
        final_score = _fallback_score(ai_prob_clamped, entropy_clamped)

    severity                  = _score_to_severity(final_score)
    prob_label, entropy_label = discretize_data(ai_prob, entropy)

    return final_score, severity, prob_label, entropy_label