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

import com.google.common.base.Preconditions;
import java.util.ArrayList;
import java.util.List;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.MethodReferenceTree;
import org.sonar.plugins.java.api.tree.MethodTree;
import org.sonar.plugins.java.api.tree.NewClassTree;

@Deprecated
public class MethodMatcher implements MethodMatchers {

  private MethodMatchers internalMatcher;

  private TypeCriteria typeCriteria;
  private NameCriteria methodName;

  private ParametersCriteria parameters;
  private List<TypeCriteria> parameterTypes;

  public static MethodMatcher create() {
    return new MethodMatcher();
  }

  public MethodMatcher copy() {
    MethodMatcher copy = new MethodMatcher();
    copy.typeCriteria = typeCriteria;
    copy.methodName = methodName;
    copy.parameterTypes = parameterTypes == null ? null : new ArrayList<>(parameterTypes);
    copy.parameters = parameterTypes == null ? null : ParametersCriteria.of(copy.parameterTypes);
    copy.updateInternalMatcher();
    return copy;
  }

  private void updateInternalMatcher() {
    if (methodName != null && parameters != null) {
      if (typeCriteria != null) {
        internalMatcher = MethodMatchers.create().ofType(typeCriteria).name(methodName).addParametersMatcher(parameters).build();
      } else {
        internalMatcher = MethodMatchers.create().ofAnyType().name(methodName).addParametersMatcher(parameters).build();
      }
    }
  }

  public MethodMatcher names(String methodName) {
    Preconditions.checkState(this.methodName == null);
    this.methodName = NameCriteria.is(methodName);
    updateInternalMatcher();
    return this;
  }

  public MethodMatcher name(NameCriteria methodName) {
    Preconditions.checkState(this.methodName == null);
    this.methodName = methodName;
    updateInternalMatcher();
    return this;
  }

  public MethodMatcher ofType(TypeCriteria typeDefinition) {
    Preconditions.checkState(this.typeCriteria == null);
    this.typeCriteria = typeDefinition;
    updateInternalMatcher();
    return this;
  }

  public MethodMatcher ofTypes(String fullyQualifiedTypeName) {
    Preconditions.checkState(typeCriteria == null);
    this.typeCriteria = TypeCriteria.is(fullyQualifiedTypeName);
    updateInternalMatcher();
    return this;
  }

  public MethodMatcher addParameter(String fullyQualifiedTypeParameterName) {
    return addParameter(TypeCriteria.is(fullyQualifiedTypeParameterName));
  }

  public MethodMatcher addParameter(TypeCriteria parameterTypeCriteria) {
    if (parameters == null) {
      parameterTypes = new ArrayList<>();
      parameters = ParametersCriteria.of(parameterTypes);
    } else {
      Preconditions.checkState(parameterTypes != null, "parameters is already initialized and doesn't support addParameter.");
    }
    parameterTypes.add(parameterTypeCriteria);
    updateInternalMatcher();
    return this;
  }

  public MethodMatcher addParametersMatcher(String... parameterTypes) {
    if (parameterTypes.length == 0) {
      return addWithoutParametersMatcher();
    }
    for (String type : parameterTypes) {
      addParameter(type);
    }
    updateInternalMatcher();
    return this;
  }

  public MethodMatcher addParametersMatcher(TypeCriteria... parameterTypes) {
    if (parameterTypes.length == 0) {
      return addWithoutParametersMatcher();
    }
    for (TypeCriteria type : parameterTypes) {
      addParameter(type);
    }
    updateInternalMatcher();
    return this;
  }

  public MethodMatcher withAnyParameters() {
    Preconditions.checkState(parameters == null);
    parameters = ParametersCriteria.any();
    updateInternalMatcher();
    return this;
  }

  public MethodMatcher addWithoutParametersMatcher() {
    Preconditions.checkState(parameters == null);
    parameters = ParametersCriteria.none();
    updateInternalMatcher();
    return this;
  }

  private void checkInternalMatcher() {
    if (internalMatcher == null) {
      throw new IllegalStateException("MethodMatcher is not fully initialized.");
    }
  }

  @Override
  public boolean matches(NewClassTree newClassTree) {
    checkInternalMatcher();
    return internalMatcher.matches(newClassTree);
  }

  @Override
  public boolean matches(MethodInvocationTree mit) {
    checkInternalMatcher();
    return internalMatcher.matches(mit);
  }

  @Override
  public boolean matches(MethodTree methodTree) {
    checkInternalMatcher();
    return internalMatcher.matches(methodTree);
  }

  @Override
  public boolean matches(MethodReferenceTree methodReferenceTree) {
    checkInternalMatcher();
    return internalMatcher.matches(methodReferenceTree);
  }

  @Override
  public boolean matches(Symbol symbol) {
    checkInternalMatcher();
    return internalMatcher.matches(symbol);
  }

}
