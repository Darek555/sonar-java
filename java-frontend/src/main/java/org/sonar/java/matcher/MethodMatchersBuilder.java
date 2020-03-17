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
package org.sonar.java.matcher;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.semantic.Type;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.MemberSelectExpressionTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodReferenceTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;

public class MethodMatchersBuilder implements MethodMatchers.Builder {

  @Nullable
  private final Predicate<Type> typePredicate;

  @Nullable
  private final Predicate<String> namePredicate;

  @Nullable
  private final Predicate<List<Type>> parametersPredicate;

  public MethodMatchersBuilder() {
    this.typePredicate = null;
    this.namePredicate = null;
    this.parametersPredicate = null;
  }

  private MethodMatchersBuilder(@Nullable Predicate<Type> typePredicate, @Nullable Predicate<String> namePredicate, @Nullable Predicate<List<Type>> parametersPredicate) {
    this.typePredicate = typePredicate;
    this.namePredicate = namePredicate;
    this.parametersPredicate = parametersPredicate;
  }

  @Override
  public Builder ofSubType(String fullyQualifiedTypeName) {
    return ofType(type -> type.isSubtypeOf(fullyQualifiedTypeName));
  }

  @Override
  public Builder ofSubTypes(String... fullyQualifiedTypeNames) {
    Builder builder = this;
    for (String name : fullyQualifiedTypeNames) {
      builder = builder.ofSubType(name);
    }
    return builder;
  }

  @Override
  public Builder ofAnyType() {
    if (typePredicate != null) {
      throw new IllegalStateException("Incompatible 'any type' added to others type predicates.");
    }
    return ofType(type -> true);
  }

  @Override
  public Builder ofType(String fullyQualifiedTypeName) {
    return ofType(type -> type.is(fullyQualifiedTypeName));
  }

  @Override
  public Builder ofTypes(String... fullyQualifiedTypeNames) {
    Builder builder = this;
    for (String name : fullyQualifiedTypeNames) {
      builder = builder.ofType(name);
    }
    return builder;
  }

  @Override
  public Builder ofType(Predicate<Type> typePredicate) {
    return new MethodMatchersBuilder(or(this.typePredicate, typePredicate), namePredicate, parametersPredicate);
  }

  @Override
  public Builder name(String methodName) {
    return name(methodName::equals);
  }

  @Override
  public Builder names(String... names) {
    Builder builder = this;
    for (String name : names) {
      builder = builder.name(name);
    }
    return builder;
  }

  @Override
  public Builder anyName() {
    if (namePredicate != null) {
      throw new IllegalStateException("Incompatible 'any name' added to others name predicates.");
    }
    return name(n -> true);
  }

  @Override
  public Builder startWithName(String name) {
    return name(n -> n.startsWith(name));
  }

  @Override
  public Builder constructor() {
    return name("<init>");
  }

  @Override
  public Builder name(Predicate<String> namePredicate) {
    return new MethodMatchersBuilder(typePredicate, or(this.namePredicate, namePredicate), parametersPredicate);
  }

  @Override
  public Builder withParameters(String... parametersType) {
    return withParameters(Arrays.stream(parametersType).<Predicate<Type>>map(parameterType -> (type -> type.is(parameterType)))
      .collect(Collectors.toList()));
  }

  @Override
  @SafeVarargs
  public final Builder withParameters(Predicate<Type>... parametersType) {
    return withParameters(Arrays.asList(parametersType));
  }

  private Builder withParameters(List<Predicate<Type>> parametersType) {
    return withParameters((List<Type> actualTypes) -> exactMatchesParameters(parametersType, actualTypes));
  }

  @Override
  public MethodMatchers.Builder withoutParameters() {
    return withParameters(Collections.emptyList());
  }

  @Override
  public MethodMatchers.Builder withAnyParameters() {
    if (parametersPredicate != null) {
      throw new IllegalStateException("Incompatible 'any parameters' constraint added to existing parameters constraint.");
    }
    return withParameters((List<Type> actualParameters) -> true);
  }

  @Override
  public Builder withParameters(Predicate<List<Type>> parametersPredicate) {
    return new MethodMatchersBuilder(typePredicate, namePredicate, or(this.parametersPredicate, parametersPredicate));
  }

  @Override
  public Builder startWithParameters(String... parametersType) {
    return startWithParameters(Arrays.stream(parametersType).<Predicate<Type>>map(parameterType -> (type -> type.is(parameterType)))
      .collect(Collectors.toList()));
  }

  @Override
  @SafeVarargs
  public final Builder startWithParameters(Predicate<Type>... parametersType) {
    return startWithParameters(Arrays.asList(parametersType));
  }

  private Builder startWithParameters(List<Predicate<Type>> parametersType) {
    return withParameters((List<Type> actualTypes) -> startWithParameters(parametersType, actualTypes));
  }

  private static boolean exactMatchesParameters(List<Predicate<Type>> expectedTypes, List<Type> actualTypes) {
    return actualTypes.size() == expectedTypes.size() && matchesParameters(expectedTypes, actualTypes);
  }

  private static boolean startWithParameters(List<Predicate<Type>> expectedTypes, List<Type> actualTypes) {
    return actualTypes.size() >= expectedTypes.size() && matchesParameters(expectedTypes, actualTypes);
  }

  private static boolean matchesParameters(List<Predicate<Type>> expectedTypes, List<Type> actualTypes) {
    for (int i = 0; i < expectedTypes.size(); i++) {
      if (!expectedTypes.get(i).test(actualTypes.get(i))) {
        return false;
      }
    }
    return true;
  }

  public boolean matches(NewClassTree newClassTree) {
    return matches(newClassTree.constructorSymbol(), null);
  }

  public boolean matches(MethodInvocationTree mit) {
    IdentifierTree id = getIdentifier(mit);
    return matches(id.symbol(), getCallSiteType(mit));
  }

  public boolean matches(MethodTree methodTree) {
    Symbol.MethodSymbol symbol = methodTree.symbol();
    Symbol.TypeSymbol enclosingClass = symbol.enclosingClass();
    return enclosingClass != null && matches(symbol, enclosingClass.type());
  }

  public boolean matches(MethodReferenceTree methodReferenceTree) {
    return matches(methodReferenceTree.method().symbol(), getCallSiteType(methodReferenceTree));
  }

  public boolean matches(Symbol symbol) {
    return matches(symbol, null);
  }

  private boolean matches(Symbol symbol, @Nullable Type callSiteType) {
    return symbol.isMethodSymbol() && isSearchedMethod((Symbol.MethodSymbol) symbol, callSiteType);
  }

  @CheckForNull
  private static Type getCallSiteType(MethodReferenceTree referenceTree) {
    Tree expression = referenceTree.expression();
    if (expression instanceof ExpressionTree) {
      return ((ExpressionTree) expression).symbolType();
    }
    return null;
  }

  @CheckForNull
  private static Type getCallSiteType(MethodInvocationTree mit) {
    ExpressionTree methodSelect = mit.methodSelect();
    // methodSelect can only be Tree.Kind.IDENTIFIER or Tree.Kind.MEMBER_SELECT
    if (methodSelect.is(Tree.Kind.IDENTIFIER)) {
      Symbol.TypeSymbol enclosingClassSymbol = ((IdentifierTree) methodSelect).symbol().enclosingClass();
      return enclosingClassSymbol != null ? enclosingClassSymbol.type() : null;
    } else {
      return ((MemberSelectExpressionTree) methodSelect).expression().symbolType();
    }
  }

  private boolean isSearchedMethod(Symbol.MethodSymbol symbol, @Nullable Type callSiteType) {
    if (typePredicate == null || namePredicate == null || parametersPredicate == null) {
      throw new IllegalStateException("MethodMatchers need to be fully initialized.");
    }
    Type type = callSiteType;
    if (type == null) {
      Symbol owner = symbol.owner();
      if (owner != null) {
        type = owner.type();
      }
    }
    return type != null &&
      namePredicate.test(symbol.name()) &&
      parametersPredicate.test(symbol.parameterTypes()) &&
      typePredicate.test(type);
  }

  private static IdentifierTree getIdentifier(MethodInvocationTree mit) {
    // methodSelect can only be Tree.Kind.IDENTIFIER or Tree.Kind.MEMBER_SELECT
    if (mit.methodSelect().is(Tree.Kind.IDENTIFIER)) {
      return (IdentifierTree) mit.methodSelect();
    }
    return ((MemberSelectExpressionTree) mit.methodSelect()).identifier();
  }

  private static <T> Predicate<T> or(@Nullable Predicate<T> accumulator, Predicate<T> next) {
    return accumulator != null ? accumulator.or(next) : next;
  }

}
