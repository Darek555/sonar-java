/*
 * SonarQube Java
 * Copyright (C) 2012-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.java.checks;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.sonar.check.Rule;
import org.sonar.java.matcher.MethodMatcher;
import org.sonar.java.matcher.TypeCriteria;
import org.sonar.java.model.JUtils;
import org.sonar.plugins.java.api.JavaFileScanner;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.semantic.Type;
import org.sonar.plugins.java.api.tree.BaseTreeVisitor;
import org.sonar.plugins.java.api.tree.BinaryExpressionTree;
import org.sonar.plugins.java.api.tree.CatchTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.IfStatementTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;

import static org.sonar.plugins.java.api.semantic.MethodMatchers.ANY;

@Rule(key = "S2629")
public class LazyArgEvaluationCheck extends BaseTreeVisitor implements JavaFileScanner {

  private static final String STRING = "java.lang.String";
  private static final String OBJECT_ARR = "java.lang.Object[]";

  interface LogLevels {
    /**
     * The methods used by the logger to log messages.
     */
    MethodMatchers log();

    /**
     * The method matcher corresponding to the test method used to check if a logger level is enabled.
     * For instance: 'isTraceEnabled()'.
     */
    MethodMatchers test();

    static Stream<LogLevels> logLevels() {
      return Stream.of(SLF4J.values(), JUL.values(), LOG4J.values())
        .flatMap(Arrays::stream);
    }

    static MethodMatcher levelTestMatcher(TypeCriteria typeDefinition, String level) {
      return MethodMatcher.create()
        .ofType(typeDefinition)
        .names(String.format("is%c%sEnabled", level.charAt(0), level.toLowerCase(Locale.ROOT).substring(1)));
    }

    enum SLF4J implements LogLevels {
      TRACE,
      DEBUG,
      INFO,
      WARN,
      ERROR
      ;

      private static final TypeCriteria LOGGER = TypeCriteria.subtypeOf("org.slf4j.Logger");
      private static final String MARKER = "org.slf4j.Marker";

      @Override
      public MethodMatchers log() {
        return MethodMatchers.create()
          .ofType(LOGGER)
          .names(toString().toLowerCase(Locale.ROOT))
          .addParametersMatcher(STRING)
          .addParametersMatcher(STRING, ANY)
          .addParametersMatcher(STRING, ANY, ANY)
          .addParametersMatcher(STRING, OBJECT_ARR)
          .addParametersMatcher(MARKER, STRING)
          .addParametersMatcher(MARKER, STRING, ANY)
          .addParametersMatcher(MARKER, STRING, ANY, ANY)
          .addParametersMatcher(MARKER, STRING, OBJECT_ARR)
          .build();
      }

      @Override
      public MethodMatcher test() {
        return LogLevels.levelTestMatcher(LOGGER, toString()).addWithoutParametersMatcher();
      }

    }

    enum JUL implements LogLevels {
      SEVERE,
      WARNING,
      INFO,
      CONFIG,
      FINE,
      FINER,
      FINEST;

      private static final String LOGGER = "java.util.logging.Logger";
      private static final MethodMatcher LOG = MethodMatcher.create()
        .ofTypes(LOGGER)
        .names("log")
        .addParameter("java.util.logging.Level")
        .addParameter(STRING);

      @Override
      public MethodMatchers log() {
        return MethodMatcher.create()
          .ofTypes(LOGGER)
          .names(toString().toLowerCase(Locale.ROOT))
          .addParameter(STRING);
      }

      @Override
      public MethodMatcher test() {
        return MethodMatcher.create()
          .ofTypes(LOGGER)
          .names("isLoggable")
          .addParameter("java.util.logging.Level");
      }
    }

    enum LOG4J implements LogLevels {
      DEBUG,
      ERROR,
      FATAL,
      INFO,
      TRACE,
      WARN;

      private static final String LEVEL = "org.apache.logging.log4j.Level";

      private static final TypeCriteria LOGGER = TypeCriteria.subtypeOf("org.apache.logging.log4j.Logger");
      private static final String MARKER = "org.apache.logging.log4j.Marker";
      private static final Predicate<Type> SUPPLIER = TypeCriteria.subtypeOf("org.apache.logging.log4j.util.Supplier")
        .or(TypeCriteria.subtypeOf("org.apache.logging.log4j.util.MessageSupplier"));

      private static final MethodMatchers TESTS = MethodMatchers.create().ofType(LOGGER).names("isEnabled")
        .addParametersMatcher(LEVEL)
        .addParametersMatcher(LEVEL, MARKER)
        .build();

      private static final MethodMatcher LOG = MethodMatcher.create().ofType(LOGGER).names("log").withAnyParameters();

      @Override
      public MethodMatchers log() {
        return MethodMatcher.create()
          .ofType(LOGGER)
          .names(toString().toLowerCase(Locale.ROOT))
          .withAnyParameters();
      }

      @Override
      public MethodMatcher test() {
        return LogLevels.levelTestMatcher(LOGGER, toString()).withAnyParameters();
      }
    }
  }

  private static final MethodMatcher PRECONDITIONS = MethodMatcher.create()
    .ofTypes("com.google.common.base.Preconditions")
    .names("checkState")
    .withAnyParameters();

  private static final MethodMatchers LAZY_ARG_METHODS = MethodMatchers.or(
    PRECONDITIONS,
    LogLevels.JUL.LOG,
    LogLevels.LOG4J.LOG,
    MethodMatchers.or(LogLevels.logLevels().map(LogLevels::log).collect(Collectors.toList())));

  private static final MethodMatchers LOG_LEVEL_TESTS = MethodMatchers.or(
    LogLevels.LOG4J.TESTS,
    MethodMatchers.or(LogLevels.logLevels().map(LogLevels::test).collect(Collectors.toList())));

  private JavaFileScannerContext context;
  private Deque<Tree> treeStack = new ArrayDeque<>();

  @Override
  public void scanFile(JavaFileScannerContext context) {
    this.context = context;
    if (context.getSemanticModel() == null) {
      return;
    }
    scan(context.getTree());
  }

  @Override
  public void visitMethodInvocation(MethodInvocationTree tree) {
    if (LAZY_ARG_METHODS.matches(tree) && !insideCatchStatement() && !insideLevelTest() && !argsUsingSuppliers(tree)) {
      onMethodInvocationFound(tree);
    }
  }

  private static boolean argsUsingSuppliers(MethodInvocationTree tree) {
    return tree.arguments().stream().map(ExpressionTree::symbolType).anyMatch(LogLevels.LOG4J.SUPPLIER::test);
  }

  @Override
  public void visitIfStatement(IfStatementTree ifTree) {
    LevelTestVisitor levelTestVisitor = new LevelTestVisitor();
    ifTree.condition().accept(levelTestVisitor);
    if (levelTestVisitor.match) {
      stackAndContinue(ifTree, super::visitIfStatement);
    } else {
      super.visitIfStatement(ifTree);
    }
  }

  @Override
  public void visitCatch(CatchTree tree) {
    stackAndContinue(tree, super::visitCatch);
  }

  @Override
  public void visitMethod(MethodTree tree) {
    // we put method trees on stack to be able to detect log statements in anonymous classes
    stackAndContinue(tree, super::visitMethod);
  }

  private boolean insideLevelTest() {
    return treeStack.stream().anyMatch(t -> t.is(Tree.Kind.IF_STATEMENT));
  }

  private boolean insideCatchStatement() {
    return treeStack.peek() != null && treeStack.peek().is(Tree.Kind.CATCH);
  }

  private <T extends Tree> void stackAndContinue(T tree, Consumer<T> visit) {
    treeStack.push(tree);
    visit.accept(tree);
    treeStack.pop();
  }

  private void onMethodInvocationFound(MethodInvocationTree mit) {
    List<JavaFileScannerContext.Location> flow = findStringArg(mit)
      .flatMap(LazyArgEvaluationCheck::checkArgument)
      .collect(Collectors.toList());
    if (!flow.isEmpty()) {
      context.reportIssue(this, flow.get(0).syntaxNode, flow.get(0).msg, flow.subList(1, flow.size()), null);
    }
  }

  private static Stream<JavaFileScannerContext.Location> checkArgument(ExpressionTree stringArgument) {
    StringExpressionVisitor visitor = new StringExpressionVisitor();
    stringArgument.accept(visitor);
    if (visitor.shouldReport) {
      return Stream.of(locationFromArg(stringArgument, visitor));
    } else {
      return Stream.empty();
    }
  }

  private static JavaFileScannerContext.Location locationFromArg(ExpressionTree stringArgument, StringExpressionVisitor visitor) {
    StringBuilder msg = new StringBuilder();
    if (visitor.hasMethodInvocation) {
      msg.append("Invoke method(s) only conditionally. ");
    }
    if (visitor.hasBinaryExpression) {
      msg.append("Use the built-in formatting to construct this argument.");
    }
    return new JavaFileScannerContext.Location(msg.toString(), stringArgument);
  }

  private static Stream<ExpressionTree> findStringArg(MethodInvocationTree mit) {
    return mit.arguments().stream()
      .filter(arg -> arg.symbolType().is("java.lang.String"));
  }

  private static class StringExpressionVisitor extends BaseTreeVisitor {

    private boolean hasBinaryExpression;
    private boolean shouldReport;
    private boolean hasMethodInvocation;

    @Override
    public void visitMethodInvocation(MethodInvocationTree tree) {
      if (!isGetter(tree) && !isAnnotationMethod(tree)) {
        shouldReport = true;
        hasMethodInvocation = true;
      }
    }

    private static boolean isGetter(MethodInvocationTree tree) {
      String methodName = tree.symbol().name();
      return methodName != null && (methodName.startsWith("get") || methodName.startsWith("is"));
    }

    private static boolean isAnnotationMethod(MethodInvocationTree tree) {
      Symbol owner = tree.symbol().owner();
      return owner.isTypeSymbol() && JUtils.isAnnotation((Symbol.TypeSymbol) owner);
    }

    @Override
    public void visitIdentifier(IdentifierTree tree) {
      if (hasBinaryExpression) {
        shouldReport = true;
      }
    }

    @Override
    public void visitNewClass(NewClassTree tree) {
      hasMethodInvocation = true;
      shouldReport = true;
    }

    @Override
    public void visitBinaryExpression(BinaryExpressionTree tree) {
      hasBinaryExpression = true;
      if (!isConstant(tree.rightOperand())) {
        tree.rightOperand().accept(this);
      }
      if (!isConstant(tree.leftOperand())) {
        tree.leftOperand().accept(this);
      }
    }

    private static boolean isConstant(ExpressionTree operand) {
      switch (operand.kind()) {
        case BOOLEAN_LITERAL:
        case CHAR_LITERAL:
        case DOUBLE_LITERAL:
        case FLOAT_LITERAL:
        case INT_LITERAL:
        case LONG_LITERAL:
        case STRING_LITERAL:
        case NULL_LITERAL:
          return true;
        case IDENTIFIER:
          return isConstant(((IdentifierTree) operand).symbol());
        case MEMBER_SELECT:
          MemberSelectExpressionTree mset = (MemberSelectExpressionTree) operand;
          return isConstant(mset.identifier().symbol());
        default:
          return false;
      }
    }

    private static boolean isConstant(Symbol symbol) {
      return symbol.isStatic() && symbol.isFinal();
    }
  }

  private static class LevelTestVisitor extends BaseTreeVisitor {
    boolean match = false;

    @Override
    public void visitMethodInvocation(MethodInvocationTree mit) {
      if (LOG_LEVEL_TESTS.matches(mit)) {
        match = true;
      }
    }
  }

}
