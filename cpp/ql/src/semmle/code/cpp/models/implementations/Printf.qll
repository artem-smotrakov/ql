import semmle.code.cpp.models.interfaces.FormattingFunction

/**
 * The standard functions `printf`, `wprintf` and their glib variants.
 */
class Printf extends FormattingFunction {
  Printf() {
    this instanceof TopLevelFunction and
    (
      hasGlobalName("printf") or
      hasGlobalName("__builtin_printf") or
      hasGlobalName("printf_s") or
      hasGlobalName("wprintf") or
      hasGlobalName("wprintf_s") or
      hasGlobalName("g_printf")
    ) and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override int getFormatParameterIndex() { result = 0 }

  override predicate isWideCharDefault() {
    hasGlobalName("wprintf") or
    hasGlobalName("wprintf_s")
  }
}

/**
 * The standard functions `fprintf`, `fwprintf` and their glib variants.
 */
class Fprintf extends FormattingFunction {
  Fprintf() {
    this instanceof TopLevelFunction and
    (
      hasGlobalName("fprintf") or
      hasGlobalName("__bultin_fprintf") or
      hasGlobalName("fwprintf") or
      hasGlobalName("g_fprintf")
    ) and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override int getFormatParameterIndex() { result = 1 }

  override predicate isWideCharDefault() { hasGlobalName("fwprintf") }

  override int getOutputParameterIndex() { result = 0 }
}

/**
 * The standard function `sprintf` and its Microsoft and glib variants.
 */
class Sprintf extends FormattingFunction {
  Sprintf() {
    this instanceof TopLevelFunction and
    (
      hasGlobalName("sprintf") or
      hasGlobalName("__builtin_sprintf") or
      hasGlobalName("_sprintf_l") or
      hasGlobalName("__swprintf_l") or
      hasGlobalName("wsprintf") or
      hasGlobalName("g_strdup_printf") or
      hasGlobalName("g_sprintf") or
      hasGlobalName("__builtin___sprintf_chk")
    ) and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override predicate isWideCharDefault() {
    getParameter(getFormatParameterIndex())
        .getType()
        .getUnspecifiedType()
        .(PointerType)
        .getBaseType()
        .getSize() > 1
  }

  override int getFormatParameterIndex() {
    hasGlobalName("g_strdup_printf") and result = 0
    or
    hasGlobalName("__builtin___sprintf_chk") and result = 3
    or
    getName() != "g_strdup_printf" and
    getName() != "__builtin___sprintf_chk" and
    result = 1
  }

  override int getOutputParameterIndex() { not hasGlobalName("g_strdup_printf") and result = 0 }

  override int getFirstFormatArgumentIndex() {
    if hasGlobalName("__builtin___sprintf_chk")
    then result = 4
    else result = getNumberOfParameters()
  }
}

/**
 * The standard functions `snprintf` and `swprintf`, and their
 * Microsoft and glib variants.
 */
class Snprintf extends FormattingFunction {
  Snprintf() {
    this instanceof TopLevelFunction and
    (
      hasGlobalName("snprintf") or // C99 defines snprintf
      hasGlobalName("__builtin_snprintf") or
      hasGlobalName("swprintf") or // The s version of wide-char printf is also always the n version
      // Microsoft has _snprintf as well as several other variations
      hasGlobalName("sprintf_s") or
      hasGlobalName("snprintf_s") or
      hasGlobalName("swprintf_s") or
      hasGlobalName("_snprintf") or
      hasGlobalName("_snprintf_s") or
      hasGlobalName("_snprintf_l") or
      hasGlobalName("_snprintf_s_l") or
      hasGlobalName("_snwprintf") or
      hasGlobalName("_snwprintf_s") or
      hasGlobalName("_snwprintf_l") or
      hasGlobalName("_snwprintf_s_l") or
      hasGlobalName("_sprintf_s_l") or
      hasGlobalName("_swprintf_l") or
      hasGlobalName("_swprintf_s_l") or
      hasGlobalName("g_snprintf") or
      hasGlobalName("wnsprintf") or
      hasGlobalName("__builtin___snprintf_chk")
    ) and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override int getFormatParameterIndex() {
    if getName().matches("%\\_l")
    then result = getFirstFormatArgumentIndex() - 2
    else result = getFirstFormatArgumentIndex() - 1
  }

  override predicate isWideCharDefault() {
    getParameter(getFormatParameterIndex())
        .getType()
        .getUnspecifiedType()
        .(PointerType)
        .getBaseType()
        .getSize() > 1
  }

  override int getOutputParameterIndex() { result = 0 }

  override int getFirstFormatArgumentIndex() {
    exists(string name |
      hasGlobalName(name)
      and (
        name = "__builtin___snprintf_chk" and
        result = 5
        or
        name != "__builtin___snprintf_chk" and
        result = getNumberOfParameters()
      )
    )
  }

  /**
   * Holds if this function returns the length of the formatted string
   * that would have been output, regardless of the amount of space
   * in the buffer.
   */
  predicate returnsFullFormatLength() {
    (
      hasGlobalName("snprintf") or
      hasGlobalName("g_snprintf") or
      hasGlobalName("__builtin___snprintf_chk") or
      hasGlobalName("snprintf_s")
    ) and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override int getSizeParameterIndex() { result = 1 }
}

/**
 * The standard functions `vprintf` and `vwprintf`, and their
 * assorted variants.
 */
class Vprintf extends FormattingFunction {
  Vprintf() {
    this instanceof TopLevelFunction and
    (
      hasGlobalName("vprintf") or
      hasGlobalName("__builtin_vprintf") or
      hasGlobalName("vfprintf") or
      hasGlobalName("__builtin_vfprintf") or
      hasGlobalName("vsprintf") or
      hasGlobalName("__builtin_vsprintf") or
      hasGlobalName("vsnprintf") or
      hasGlobalName("__builtin_vsnprintf") or
      hasGlobalName("vprintf_s") or
      hasGlobalName("vfprintf_s") or
      hasGlobalName("vsprintf_s") or
      hasGlobalName("vsnprintf_s") or
      hasGlobalName("_vsnprintf_s") or
      hasGlobalName("_vsnprintf_s_l") or
      hasGlobalName("vwprintf") or
      hasGlobalName("vfwprintf") or
      hasGlobalName("vswprintf") or
      hasGlobalName("vwprintf_s") or
      hasGlobalName("vfwprintf_s") or
      hasGlobalName("vswprintf_s") or
      hasGlobalName("_vsnwprintf_s") or
      hasGlobalName("_vsnwprintf_s_l")
    ) and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override int getFormatParameterIndex() {
    if getName().matches("%\\_l")
    then result = getFirstFormatArgumentIndex() - 3
    else result = getFirstFormatArgumentIndex() - 2
  }

  override int getFirstFormatArgumentIndex() { result = getNumberOfParameters() - 1 }

  override predicate isWideCharDefault() { getName().matches("%w%") }

  override int getOutputParameterIndex() {
    not (getName().matches("%vprintf%") or getName().matches("%vwprintf%")) and
    result = 0
  }

  /**
   * Holds if this function returns the length of the formatted string
   * that would have been output, regardless of the amount of space
   * in the buffer.
   */
  predicate returnsFullFormatLength() {
    (
      hasGlobalName("vsnprintf") or
      hasGlobalName("__builtin_vsnprintf")
    ) and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override int getSizeParameterIndex() { getName().matches("%sn%") and result = 1 }
}

/**
 * The Microsoft `StringCchPrintf` function and variants.
 */
class StringCchPrintf extends FormattingFunction {
  StringCchPrintf() {
    this instanceof TopLevelFunction and
    (
      hasGlobalName("StringCchPrintf") or
      hasGlobalName("StringCchPrintfEx") or
      hasGlobalName("StringCchPrintf_l") or
      hasGlobalName("StringCchPrintf_lEx") or
      hasGlobalName("StringCbPrintf") or
      hasGlobalName("StringCbPrintfEx") or
      hasGlobalName("StringCbPrintf_l") or
      hasGlobalName("StringCbPrintf_lEx")
    ) and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override int getFormatParameterIndex() {
    if getName().matches("%Ex") then result = 5 else result = 2
  }

  override predicate isWideCharDefault() {
    getParameter(getFormatParameterIndex())
        .getType()
        .getUnspecifiedType()
        .(PointerType)
        .getBaseType()
        .getSize() > 1
  }

  override int getOutputParameterIndex() { result = 0 }

  override int getSizeParameterIndex() { result = 1 }
}

/**
 * The standard function `syslog`.
 */
class Syslog extends FormattingFunction {
  Syslog() {
    this instanceof TopLevelFunction and
    hasGlobalName("syslog") and
    not exists(getDefinition().getFile().getRelativePath())
  }

  override int getFormatParameterIndex() { result = 1 }
}
