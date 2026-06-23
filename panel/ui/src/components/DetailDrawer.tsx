import { postJson } from "@/lib/api";
import { SelectMenu, TextAreaField } from "@/components/Controls";
import { formatValue } from "@/lib/format";
import { translate } from "@/lib/i18n";
import { roleAllows } from "@/lib/rbac";
import type { Language, PanelRecord, PanelRole } from "@/types";
import { X } from "lucide-react";
import { useEffect, useState } from "react";

type ReviewTargetType = "finding" | "incident" | "baseline_drift";
type ReviewValue = {
  verdict?: string;
  note?: string;
  reviewer?: string;
  reviewed_at?: string;
  target_type?: string;
  target_id?: string;
  review_signature?: string;
};
type ReviewResponse = { ok?: boolean; review?: ReviewValue };

export function DetailDrawer({
  row,
  dataset,
  role,
  language,
  onClose,
  onSaved,
}: {
  row: PanelRecord | null;
  dataset: string;
  role: PanelRole;
  language: Language;
  onClose: () => void;
  onSaved: (review?: ReviewValue) => void;
}) {
  const [note, setNote] = useState("");
  const [verdict, setVerdict] = useState("needs_review");
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ type: "ok" | "error"; text: string } | null>(null);
  const [localReview, setLocalReview] = useState<ReviewValue | null>(null);
  const rowKey = row ? `${dataset}:${String(row.id || row.finding_id || "")}` : "";
  useEffect(() => {
    const review = reviewValue(row);
    setVerdict(review?.verdict || "needs_review");
    setNote(review?.note || "");
    setLocalReview(review);
    setMessage(null);
  }, [rowKey]);
  if (!row) return null;
  const reviewTarget = reviewTargetFromDataset(dataset);
  const targetId = reviewTarget ? String(row.id || row.finding_id || "") : "";
  const currentReview = localReview || reviewValue(row);

  async function saveReview() {
    if (!reviewTarget || !targetId) {
      setMessage({ type: "error", text: translate(language, "reviewTargetMissing") });
      return;
    }
    setSaving(true);
    setMessage(null);
    try {
      const response = await postJson<ReviewResponse>("/review", role, {
        target_type: reviewTarget,
        target_id: targetId,
        verdict,
        note,
        reviewer: "panel",
      });
      const savedReview = response.review || {
        target_type: reviewTarget,
        target_id: targetId,
        verdict,
        note,
        reviewer: "panel",
        reviewed_at: new Date().toISOString(),
      };
      setLocalReview(savedReview);
      setMessage({ type: "ok", text: translate(language, "saved") });
      onSaved(savedReview);
    } catch (error) {
      setMessage({
        type: "error",
        text: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="detail-drawer" onClick={(event) => event.stopPropagation()}>
        <header>
          <div>
            <span>{translate(language, "details")}</span>
            <h2>{String(row.title || row.rule_id || row.id || "-")}</h2>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label={translate(language, "close")}>
            <X size={18} />
          </button>
        </header>
        <dl className="detail-list">
          {Object.entries(row)
            .filter(([key]) => !["id", "finding_id", "evidence", "impact", "recommendations", "payload", "review", "review_verdict", "review_signature"].includes(key))
            .slice(0, 18)
            .map(([key, value]) => (
              <div key={key}>
                <dt>{translate(language, key)}</dt>
                <dd>{formatValue(key, value, language)}</dd>
              </div>
            ))}
        </dl>
        {roleAllows(role, "admin") && (
          <section className="review-box">
            <h3>{translate(language, "reviewRecord")}</h3>
            {currentReview?.verdict && (
              <p className="review-meta">
                <span>{translate(language, "reviewStatus")}: {translate(language, currentReview.verdict)}</span>
                {currentReview.reviewed_at && <span>{translate(language, "reviewedAt")}: {formatValue("reviewed_at", currentReview.reviewed_at, language)}</span>}
              </p>
            )}
            <p className="review-scope-note">{translate(language, "reviewScopeSimilar")}</p>
            <SelectMenu
              value={verdict}
              ariaLabel={translate(language, "reviewRecord")}
              options={["needs_review", "confirmed", "false_positive"].map((item) => ({
                value: item,
                label: translate(language, item),
              }))}
              onChange={setVerdict}
            />
            <TextAreaField value={note} onChange={setNote} placeholder={translate(language, "reviewNote")} />
            {message && <p className={`review-message review-message-${message.type}`}>{message.text}</p>}
            <button className="primary-button" type="button" disabled={saving || !reviewTarget || !targetId} onClick={saveReview}>
              {saving ? translate(language, "loading") : translate(language, currentReview ? "updateReview" : "saveReview")}
            </button>
          </section>
        )}
      </aside>
    </div>
  );
}

function reviewTargetFromDataset(dataset: string): ReviewTargetType | null {
  if (dataset === "findings") return "finding";
  if (dataset === "incidents") return "incident";
  if (dataset === "baseline_drifts") return "baseline_drift";
  return null;
}

function reviewValue(row: PanelRecord | null): ReviewValue | null {
  if (!row || typeof row.review !== "object" || row.review === null) return null;
  const review = row.review as Record<string, unknown>;
  return {
    verdict: typeof review.verdict === "string" ? review.verdict : undefined,
    note: typeof review.note === "string" ? review.note : undefined,
    reviewer: typeof review.reviewer === "string" ? review.reviewer : undefined,
    reviewed_at: typeof review.reviewed_at === "string" ? review.reviewed_at : undefined,
    target_type: typeof review.target_type === "string" ? review.target_type : undefined,
    target_id: typeof review.target_id === "string" ? review.target_id : undefined,
    review_signature: typeof review.review_signature === "string" ? review.review_signature : undefined,
  };
}
