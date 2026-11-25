// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only
// 本版权头任何人不得更改/删除。

//! xiaolishaxiang 租户策略引擎：TOML 规则、allow/deny/log/alert、加载前冲突检测。

use serde::Deserialize;
use std::fmt;

/// 单个规则的执行动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
    Log,
    Alert,
}

/// 策略评估结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Log,
    Alert,
}

impl Decision {
    /// 是否允许执行。
    #[must_use]
    pub fn is_allowed(self) -> bool {
        !matches!(self, Self::Deny)
    }
}

/// 一条策略规则。
///
/// program 支持两种匹配：
/// - 精确匹配：`/usr/bin/python3`
/// - 前缀匹配：以 `*` 结尾，如 `/usr/bin/*`
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    pub action: RuleAction,
    pub programs: Vec<String>,
}

/// 租户策略。
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    /// 默认动作；缺省 allow 以保持当前无策略租户行为兼容。
    #[serde(default = "default_action")]
    pub default_action: RuleAction,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

const fn default_action() -> RuleAction {
    RuleAction::Allow
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_action: RuleAction::Allow,
            rules: Vec::new(),
        }
    }
}

/// 策略加载/校验错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Toml(String),
    EmptyRuleName,
    EmptyPrograms(String),
    DuplicateRuleName(String),
    ConflictingRules {
        pattern: String,
        first: String,
        second: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(e) => write!(f, "TOML 解析失败: {e}"),
            Self::EmptyRuleName => write!(f, "规则 name 不能为空"),
            Self::EmptyPrograms(name) => write!(f, "规则 {name} 的 programs 不能为空"),
            Self::DuplicateRuleName(name) => write!(f, "规则 name 重复: {name}"),
            Self::ConflictingRules {
                pattern,
                first,
                second,
            } => write!(
                f,
                "规则冲突: pattern '{pattern}' 同时被 '{first}' 与 '{second}' 以不同动作覆盖"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// 从 TOML 字符串解析并执行 dry-run 校验。
    pub fn from_toml(input: &str) -> Result<Self, PolicyError> {
        let policy: Self = toml::from_str(input).map_err(|e| PolicyError::Toml(e.to_string()))?;
        policy.dry_run()?;
        Ok(policy)
    }

    /// 加载前 dry-run：结构校验 + 冲突检测。
    pub fn dry_run(&self) -> Result<(), PolicyError> {
        let mut names = std::collections::HashSet::new();
        let mut exact_actions: std::collections::HashMap<String, (RuleAction, String)> =
            std::collections::HashMap::new();

        for rule in &self.rules {
            let name = rule.name.trim();
            if name.is_empty() {
                return Err(PolicyError::EmptyRuleName);
            }
            if !names.insert(name.to_string()) {
                return Err(PolicyError::DuplicateRuleName(name.to_string()));
            }
            if rule.programs.is_empty() {
                return Err(PolicyError::EmptyPrograms(name.to_string()));
            }

            for raw in &rule.programs {
                let pattern = normalize_pattern(raw);
                if pattern.is_empty() {
                    return Err(PolicyError::EmptyPrograms(name.to_string()));
                }
                if let Some(stripped) = pattern.strip_prefix("exact:") {
                    if let Some((action, first_rule)) = exact_actions.get(stripped) {
                        if *action != rule.action {
                            return Err(PolicyError::ConflictingRules {
                                pattern: stripped.to_string(),
                                first: first_rule.clone(),
                                second: name.to_string(),
                            });
                        }
                    } else {
                        exact_actions.insert(stripped.to_string(), (rule.action, name.to_string()));
                    }
                }
            }
        }
        Ok(())
    }

    /// 评估指定 program 是否允许执行。
    ///
    /// 决策顺序：
    /// 1. 命中最长 pattern 的规则优先（支持更具体例外）
    /// 2. 相同长度命中多条规则时，deny 优先（失败关闭）
    /// 3. 无命中时使用 default_action
    #[must_use]
    pub fn evaluate(&self, program: &str) -> Decision {
        let mut best: Option<(usize, RuleAction)> = None;

        for rule in &self.rules {
            for raw in &rule.programs {
                let pattern = normalize_pattern(raw);
                if !matches_pattern(&pattern, program) {
                    continue;
                }
                let specificity = pattern.len();
                match best {
                    None => best = Some((specificity, rule.action)),
                    Some((best_len, best_action))
                        if specificity > best_len
                            || (specificity == best_len
                                && action_priority(rule.action) > action_priority(best_action)) =>
                    {
                        best = Some((specificity, rule.action));
                    }
                    _ => {}
                }
            }
        }

        match best {
            Some((_, action)) => map_action(action),
            None => map_action(self.default_action),
        }
    }
}

fn map_action(action: RuleAction) -> Decision {
    match action {
        RuleAction::Allow => Decision::Allow,
        RuleAction::Deny => Decision::Deny,
        RuleAction::Log => Decision::Log,
        RuleAction::Alert => Decision::Alert,
    }
}

/// deny 优先级最高，其次 alert/log，最后 allow。
const fn action_priority(action: RuleAction) -> u8 {
    match action {
        RuleAction::Deny => 4,
        RuleAction::Alert => 3,
        RuleAction::Log => 2,
        RuleAction::Allow => 1,
    }
}

fn normalize_pattern(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(prefix) = trimmed.strip_suffix('*') {
        format!("prefix:{}", prefix.trim_end_matches('/'))
    } else {
        format!("exact:{trimmed}")
    }
}

fn matches_pattern(normalized: &str, program: &str) -> bool {
    if let Some(prefix) = normalized.strip_prefix("prefix:") {
        if prefix.is_empty() {
            return true;
        }
        return program == prefix || program.starts_with(&format!("{prefix}/"));
    }
    normalized.strip_prefix("exact:") == Some(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_policy() {
        let policy = Policy::from_toml(
            r#"
default_action = "deny"

[[rule]]
name = "allow-coreutils"
action = "allow"
programs = ["/bin/true", "/bin/echo"]

[[rule]]
name = "deny-shells"
action = "deny"
programs = ["/bin/sh", "/bin/bash"]
"#,
        )
        .expect("valid policy");
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.evaluate("/bin/true"), Decision::Allow);
        assert_eq!(policy.evaluate("/bin/sh"), Decision::Deny);
        assert_eq!(policy.evaluate("/usr/bin/python3"), Decision::Deny);
    }

    #[test]
    fn prefix_rules_support_more_specific_allow_exception() {
        let policy = Policy::from_toml(
            r#"
[[rule]]
name = "deny-usr-bin"
action = "deny"
programs = ["/usr/bin/*"]

[[rule]]
name = "allow-python"
action = "allow"
programs = ["/usr/bin/python3"]
"#,
        )
        .expect("prefix exception should be allowed");
        assert_eq!(policy.evaluate("/usr/bin/python3"), Decision::Allow);
        assert_eq!(policy.evaluate("/usr/bin/curl"), Decision::Deny);
        assert_eq!(policy.evaluate("/bin/true"), Decision::Allow);
    }

    #[test]
    fn rejects_exact_pattern_action_conflict() {
        let err = Policy::from_toml(
            r#"
[[rule]]
name = "allow-true"
action = "allow"
programs = ["/bin/true"]

[[rule]]
name = "deny-true"
action = "deny"
programs = ["/bin/true"]
"#,
        )
        .expect_err("same exact pattern with different actions must conflict");
        assert!(matches!(err, PolicyError::ConflictingRules { .. }));
    }

    #[test]
    fn rejects_duplicate_rule_name() {
        let err = Policy::from_toml(
            r#"
[[rule]]
name = "dup"
action = "allow"
programs = ["/bin/true"]

[[rule]]
name = "dup"
action = "deny"
programs = ["/bin/false"]
"#,
        )
        .expect_err("duplicate names rejected");
        assert_eq!(err, PolicyError::DuplicateRuleName("dup".to_string()));
    }

    #[test]
    fn rejects_empty_programs() {
        let err = Policy::from_toml(
            r#"
[[rule]]
name = "empty"
action = "allow"
programs = []
"#,
        )
        .expect_err("empty programs rejected");
        assert_eq!(err, PolicyError::EmptyPrograms("empty".to_string()));
    }

    #[test]
    fn rejects_unknown_action() {
        let err = Policy::from_toml(
            r#"
[[rule]]
name = "bad"
action = "audit"
programs = ["/bin/true"]
"#,
        )
        .expect_err("unknown action rejected");
        assert!(matches!(err, PolicyError::Toml(_)));
    }

    #[test]
    fn default_action_is_allow_when_no_rule_matches() {
        let policy = Policy::default();
        assert_eq!(policy.evaluate("/bin/true"), Decision::Allow);
        assert!(Decision::Log.is_allowed());
        assert!(Decision::Alert.is_allowed());
        assert!(!Decision::Deny.is_allowed());
    }

    #[test]
    fn deny_wins_on_same_specificity() {
        let policy = Policy::from_toml(
            r#"
[[rule]]
name = "allow-prefix"
action = "allow"
programs = ["/opt/*"]

[[rule]]
name = "alert-prefix"
action = "alert"
programs = ["/opt/*"]

[[rule]]
name = "deny-prefix"
action = "deny"
programs = ["/opt/*"]
"#,
        )
        .expect("same specificity overlap is allowed; deny wins at runtime");
        assert_eq!(policy.evaluate("/opt/tool"), Decision::Deny);
    }
}
