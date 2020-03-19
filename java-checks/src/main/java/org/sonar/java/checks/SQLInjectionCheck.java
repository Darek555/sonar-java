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

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.sonar.check.Rule;
import org.sonar.java.matcher.MethodMatcher;
import org.sonar.java.matcher.TypeCriteria;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.AssignmentExpressionTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;

import static org.sonar.java.checks.helpers.ReassignmentFinder.getInitializerOrExpression;
import static org.sonar.java.checks.helpers.ReassignmentFinder.getReassignments;

@Rule(key = "S2077")
public class SQLInjectionCheck extends IssuableSubscriptionVisitor {

  private static final String JAVA_SQL_STATEMENT = "java.sql.Statement";
  private static final String JAVA_SQL_CONNECTION = "java.sql.Connection";
  private static final String SPRING_JDBC_OPERATIONS = "org.springframework.jdbc.core.JdbcOperations";

  private static final MethodMatchers SQL_INJECTION_SUSPECTS = MethodMatchers.or(
    MethodMatcher.create().ofType(TypeCriteria.subtypeOf("org.hibernate.Session")).names("createQuery").withAnyParameters(),
    MethodMatcher.create().ofType(TypeCriteria.subtypeOf("org.hibernate.Session")).names("createSQLQuery").withAnyParameters(),

    matcherBuilder(JAVA_SQL_STATEMENT).names("executeQuery").withAnyParameters(),
    matcherBuilder(JAVA_SQL_STATEMENT).names("execute").withAnyParameters(),
    matcherBuilder(JAVA_SQL_STATEMENT).names("executeUpdate").withAnyParameters(),
    matcherBuilder(JAVA_SQL_STATEMENT).names("executeLargeUpdate").withAnyParameters(),
    matcherBuilder(JAVA_SQL_STATEMENT).names("addBatch").withAnyParameters(),

    matcherBuilder(JAVA_SQL_CONNECTION).names("prepareStatement").withAnyParameters(),
    matcherBuilder(JAVA_SQL_CONNECTION).names("prepareCall").withAnyParameters(),
    matcherBuilder(JAVA_SQL_CONNECTION).names("nativeSQL").withAnyParameters(),

    MethodMatcher.create().ofTypes("javax.persistence.EntityManager").names("createNativeQuery").withAnyParameters(),
    MethodMatcher.create().ofTypes("javax.persistence.EntityManager").names("createQuery").withAnyParameters(),

    matcherBuilder(SPRING_JDBC_OPERATIONS).names("batchUpdate").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("execute").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("query").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("queryForList").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("queryForMap").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("queryForObject").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("queryForRowSet").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("queryForInt").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("queryForLong").withAnyParameters(),
    matcherBuilder(SPRING_JDBC_OPERATIONS).names("update").withAnyParameters(),
    MethodMatcher.create().ofTypes("org.springframework.jdbc.core.PreparedStatementCreatorFactory").names("<init>").withAnyParameters(),
    MethodMatcher.create().ofTypes("org.springframework.jdbc.core.PreparedStatementCreatorFactory").names("newPreparedStatementCreator").withAnyParameters(),

    matcherBuilder("javax.jdo.PersistenceManager").names("newQuery").withAnyParameters(),
    matcherBuilder("javax.jdo.Query").names("setFilter").withAnyParameters(),
    matcherBuilder("javax.jdo.Query").names("setGrouping").withAnyParameters()
  );

  private static MethodMatcher matcherBuilder(String typeFQN) {
    return MethodMatcher.create().ofType(TypeCriteria.subtypeOf(typeFQN));
  }

  @Override
  public List<Tree.Kind> nodesToVisit() {
    return Arrays.asList(Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS);
  }

  @Override
  public void visitNode(Tree tree) {
    if (anyMatch(tree)) {
      Optional<ExpressionTree> sqlStringArg = arguments(tree)
        .filter(arg -> arg.symbolType().is("java.lang.String"))
        .findFirst();
      sqlStringArg.filter(SQLInjectionCheck::isDynamicString)
        .ifPresent(arg -> reportIssue(arg, "Ensure that string concatenation is required and safe for this SQL query."));
    }
  }

  private static Stream<ExpressionTree> arguments(Tree methodTree) {
    if (methodTree.is(Tree.Kind.METHOD_INVOCATION)) {
      return ((MethodInvocationTree) methodTree).arguments().stream();
    }
    if (methodTree.is(Tree.Kind.NEW_CLASS)) {
      return ((NewClassTree) methodTree).arguments().stream();
    }
    return Stream.empty();
  }

  private static boolean anyMatch(Tree tree) {
    if (!hasArguments(tree)) {
      return false;
    }
    if (tree.is(Tree.Kind.NEW_CLASS)) {
      return SQL_INJECTION_SUSPECTS.matches((NewClassTree) tree);
    }
    if (tree.is(Tree.Kind.METHOD_INVOCATION)) {
      return SQL_INJECTION_SUSPECTS.matches((MethodInvocationTree) tree);
    }
    return false;
  }

  private static boolean hasArguments(Tree tree) {
    return arguments(tree).findAny().isPresent();
  }

  private static boolean isDynamicString(ExpressionTree arg) {
    if (arg.is(Tree.Kind.PLUS_ASSIGNMENT)) {
      return !((AssignmentExpressionTree) arg).expression().asConstant().isPresent();
    }
    if (arg.is(Tree.Kind.IDENTIFIER)) {
      Symbol symbol = ((IdentifierTree) arg).symbol();
      ExpressionTree initializerOrExpression = getInitializerOrExpression(symbol.declaration());
      return (initializerOrExpression != null && isDynamicString(initializerOrExpression)) || getReassignments(symbol.owner().declaration(), symbol.usages()).stream()
        .anyMatch(SQLInjectionCheck::isDynamicString);
    }
    return arg.is(Tree.Kind.PLUS) && !arg.asConstant().isPresent();
  }
}
