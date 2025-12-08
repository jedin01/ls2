package ao.sudojed.lss.resolver;

import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;

/**
 * Resolve argumentos do tipo LazyUser automaticamente nos controllers.
 * 
 * <h2>Uso</h2>
 * <pre>{@code
 * @GetMapping("/profile")
 * public User getProfile(LazyUser user) {  // Injetado automaticamente!
 *     return userService.findById(user.getId());
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
public class LazyUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return LazyUser.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        return LazySecurityContext.getCurrentUser();
    }
}
